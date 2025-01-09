use std::collections::{BTreeSet, HashSet};

use anyhow::{ensure, Result};
use c_kzg::{
    Blob as CKzgBlob, Bytes48, Cell as CKzgCell, KzgProof as CKzgProof, CELLS_PER_EXT_BLOB,
};
use helper_functions::{misc, predicates::is_valid_merkle_branch};
use itertools::Itertools as _;
use kzg as _;
use num_traits::One as _;
use sha2::{Digest as _, Sha256};
use ssz::{ByteVector, ContiguousList, ContiguousVector, SszHash as _, Uint256};
use try_from_iterator::TryFromIterator as _;
use types::{
    combined::SignedBeaconBlock,
    config::Config,
    deneb::primitives::{Blob, KzgProof},
    fulu::{
        containers::{DataColumnSidecar, MatrixEntry},
        primitives::{Cell, ColumnIndex, CustodyIndex},
    },
    phase0::primitives::{NodeId, SubnetId},
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

use error::Error;
use trusted_setup::settings;

mod error;
mod trusted_setup;

#[cfg(test)]
mod tests;

type ColumnCells = [Cell; CELLS_PER_EXT_BLOB];
type ColumnProofs = [KzgProof; CELLS_PER_EXT_BLOB];
type CellsAndKzgProofs = Vec<(ColumnCells, ColumnProofs)>;

#[cfg(feature = "metrics")]
use prometheus_metrics::METRICS;

pub fn get_custody_groups(
    raw_node_id: [u8; 32],
    custody_group_count: u64,
    config: &Config,
) -> Result<Vec<CustodyIndex>> {
    let number_of_custody_groups = config.number_of_custody_groups;
    ensure!(
        custody_group_count <= number_of_custody_groups,
        Error::InvalidCustodyGroupCount {
            custody_group_count,
            number_of_custody_groups,
        },
    );

    let mut current_id = NodeId::from_be_bytes(raw_node_id);

    let mut custody_groups = BTreeSet::new();
    while (custody_groups.len() as u64) < custody_group_count {
        let mut hasher = Sha256::new();
        let mut bytes = [0u8; 32];

        current_id.into_raw().to_little_endian(&mut bytes);

        hasher.update(bytes);
        bytes = hasher.finalize().into();

        let output_prefix = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ];

        let output_prefix_u64 = u64::from_le_bytes(output_prefix);
        let custody_group = output_prefix_u64
            .checked_rem(number_of_custody_groups)
            .expect("number of custody groups must not be zero");
        custody_groups.insert(custody_group);

        if current_id == Uint256::MAX {
            // > Overflow prevention
            current_id = Uint256::ZERO;
        } else {
            current_id = current_id + Uint256::one();
        }
    }

    Ok(custody_groups.into_iter().collect())
}

pub fn compute_columns_for_custody_group(
    custody_group: CustodyIndex,
    config: &Config,
) -> Result<impl Iterator<Item = ColumnIndex>> {
    let number_of_custody_groups = config.number_of_custody_groups;
    ensure!(
        custody_group < number_of_custody_groups,
        Error::InvalidCustodyGroup {
            custody_group,
            number_of_custody_groups,
        },
    );

    let mut columns = Vec::new();
    for i in 0..config.columns_per_group() {
        columns.push(ColumnIndex::from(
            number_of_custody_groups * i + custody_group,
        ));
    }

    columns.sort_unstable();
    Ok(columns.into_iter())
}

pub fn compute_subnets_from_custody_group(
    custody_group: CustodyIndex,
    config: &Config,
) -> Result<impl Iterator<Item = SubnetId> + '_> {
    let subnets = compute_columns_for_custody_group(custody_group, config)?
        .map(|column_index| misc::compute_subnet_for_data_column_sidecar(config, column_index))
        .unique();

    Ok(subnets)
}

pub fn compute_subnets_for_node(
    raw_node_id: [u8; 32],
    custody_group_count: u64,
    config: &Config,
) -> Result<HashSet<SubnetId>> {
    let mut subnets = HashSet::new();
    for custody_group in get_custody_groups(raw_node_id, custody_group_count, config)? {
        let custody_group_subnets = compute_subnets_from_custody_group(custody_group, config)?;

        subnets.extend(custody_group_subnets);
    }

    Ok(subnets)
}

/// Verify if the data column sidecar is valid.
pub fn verify_data_column_sidecar<P: Preset>(
    data_column_sidecar: &DataColumnSidecar<P>,
    config: &Config,
) -> bool {
    let DataColumnSidecar {
        index,
        column,
        kzg_commitments,
        kzg_proofs,
        ..
    } = data_column_sidecar;

    // The sidecar index must be within the valid range
    if *index >= config.number_of_columns {
        return false;
    }

    // A sidecar for zero blobs is invalid
    if kzg_commitments.len() == 0 {
        return false;
    }

    // The column length must be equal to the number of commitments/proofs
    if column.len() != kzg_commitments.len() || column.len() != kzg_proofs.len() {
        return false;
    }

    true
}

/// Verify if the KZG proofs are correct.
pub fn verify_kzg_proofs<P: Preset>(data_column_sidecar: &DataColumnSidecar<P>) -> Result<bool> {
    #[cfg(feature = "metrics")]
    let _timer = METRICS.get().map(|metrics| {
        metrics
            .data_column_sidecar_kzg_verification_batch
            .start_timer()
    });

    let DataColumnSidecar {
        index,
        column,
        kzg_commitments,
        kzg_proofs,
        ..
    } = data_column_sidecar;

    let cell_indices: Vec<u64> = vec![*index; column.len()];

    let cells = column
        .clone()
        .into_iter()
        .map(|a| CKzgCell::from_bytes(a.as_bytes()).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let commitments = kzg_commitments
        .iter()
        .map(|a| Bytes48::from_bytes(a.as_bytes()).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let kzg_proofs = kzg_proofs
        .iter()
        .map(|a| Bytes48::from_bytes(a.as_bytes()).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    CKzgProof::verify_cell_kzg_proof_batch(
        commitments.as_slice(),
        cell_indices.as_slice(),
        cells.as_slice(),
        kzg_proofs.as_slice(),
        settings(),
    )
    .map_err(Into::into)
}

pub fn verify_sidecar_inclusion_proof<P: Preset>(
    data_column_sidecar: &DataColumnSidecar<P>,
) -> bool {
    #[cfg(feature = "metrics")]
    let _timer = METRICS.get().map(|metrics| {
        metrics
            .data_column_sidecar_inclusion_proof_verification
            .start_timer()
    });

    let DataColumnSidecar {
        kzg_commitments,
        signed_block_header,
        kzg_commitments_inclusion_proof,
        ..
    } = data_column_sidecar;

    // Fields in BeaconBlockBody before blob KZG commitments
    let index_at_commitment_depth = 11;

    // is_valid_blob_sidecar_inclusion_proof
    is_valid_merkle_branch(
        kzg_commitments.hash_tree_root(),
        *kzg_commitments_inclusion_proof,
        index_at_commitment_depth,
        signed_block_header.message.body_root,
    )
}

/**
 * Return the full, flattened sequence of matrix entries.
 *
 * This helper demonstrates the relationship between blobs and the matrix of cells/proofs.
 */
pub fn compute_matrix(blobs: &[CKzgBlob]) -> Result<Vec<MatrixEntry>> {
    let mut matrix = vec![];
    for (blob_index, blob) in blobs.iter().enumerate() {
        let (cells, proofs) = CKzgCell::compute_cells_and_kzg_proofs(blob, settings())?;
        for (cell_index, (cell, proof)) in cells.into_iter().zip(proofs.into_iter()).enumerate() {
            matrix.push(MatrixEntry {
                cell: try_convert_to_cell(&cell)?,
                kzg_proof: KzgProof::from(proof.to_bytes().into_inner()),
                row_index: blob_index as u64,
                column_index: cell_index as u64,
            });
        }
    }

    Ok(matrix)
}

/**
 * Recover the full, flattened sequence of matrix entries.
 *
 * This helper demonstrates how to apply ``recover_cells_and_kzg_proofs``.
 */
pub fn recover_matrix(
    partial_matrix: &[MatrixEntry],
    blob_count: usize,
) -> Result<Vec<MatrixEntry>> {
    #[cfg(feature = "metrics")]
    let _timer = METRICS
        .get()
        .map(|metrics| metrics.columns_reconstruction_time.start_timer());

    let mut matrix = vec![];
    for blob_index in 0..blob_count {
        let (cell_indexs, cells_bytes): (Vec<_>, Vec<_>) = partial_matrix
            .iter()
            .filter(|&e| (e.row_index == blob_index as u64))
            .map(|e| (e.column_index, e.cell.as_bytes()))
            .unzip();

        let cells = cells_bytes
            .into_iter()
            .map(|c| CKzgCell::from_bytes(c).map_err(Into::into))
            .collect::<Result<Vec<CKzgCell>>>()?;

        let (recovered_cells, recovered_proofs) =
            CKzgCell::recover_cells_and_kzg_proofs(&cell_indexs, &cells, settings())?;

        for (cell_index, (cell, proof)) in recovered_cells
            .into_iter()
            .zip(recovered_proofs.into_iter())
            .enumerate()
        {
            matrix.push(MatrixEntry {
                cell: try_convert_to_cell(&cell)?,
                kzg_proof: KzgProof::from(proof.to_bytes().into_inner()),
                row_index: blob_index as u64,
                column_index: cell_index as u64,
            });
        }
    }

    Ok(matrix)
}

pub fn construct_data_column_sidecars<P: Preset>(
    signed_block: &SignedBeaconBlock<P>,
    cells_and_kzg_proofs: &CellsAndKzgProofs,
    config: &Config,
) -> Result<Vec<DataColumnSidecar<P>>> {
    let signed_block_header = signed_block.to_header();

    let mut sidecars: Vec<DataColumnSidecar<P>> = Vec::new();
    if let Some(post_electra_beacon_block_body) = signed_block.message().body().post_electra() {
        let kzg_commitments = post_electra_beacon_block_body.blob_kzg_commitments();

        if kzg_commitments.is_empty() {
            return Ok(vec![]);
        }

        let blob_count = cells_and_kzg_proofs.len();
        ensure!(
            kzg_commitments.len() == blob_count,
            Error::BlobCommitmentsLengthMismatch {
                blob_count,
                commitments_length: kzg_commitments.len(),
            }
        );

        let kzg_commitments_inclusion_proof =
            misc::kzg_commitments_inclusion_proof(post_electra_beacon_block_body);

        for column_index in 0..config.number_of_columns() {
            let column = ContiguousList::try_from_iter(
                (0..blob_count)
                    .map(|row_index| cells_and_kzg_proofs[row_index].0[column_index].clone()),
            )?;
            let kzg_proofs = ContiguousList::try_from_iter(
                (0..blob_count).map(|row_index| cells_and_kzg_proofs[row_index].1[column_index]),
            )?;

            sidecars.push(DataColumnSidecar {
                index: ColumnIndex::try_from(column_index)?,
                column,
                kzg_commitments: kzg_commitments.clone(),
                kzg_proofs,
                signed_block_header,
                kzg_commitments_inclusion_proof,
            });
        }
    }

    Ok(sidecars)
}

pub fn try_convert_to_cells_and_kzg_proofs<P: Preset>(
    blobs: impl Iterator<Item = Blob<P>>,
) -> Result<CellsAndKzgProofs> {
    let cells_and_kzg_proofs = blobs
        .map(|blob| {
            let c_kzg_blob = CKzgBlob::from_bytes(blob.as_bytes())?;
            CKzgCell::compute_cells_and_kzg_proofs(&c_kzg_blob, settings()).map_err(Into::into)
        })
        .collect::<Result<Vec<_>>>()?;

    let mut result = vec![];
    for (cells, proofs) in cells_and_kzg_proofs {
        let cells = cells
            .iter()
            .map(try_convert_to_cell)
            .collect::<Result<Vec<_>>>()?;
        let column_cells = cells
            .try_into()
            .expect("column cells should have length of CELLS_PER_EXT_BLOB");

        let proofs = proofs
            .iter()
            .map(|proof| KzgProof::from(proof.to_bytes().into_inner()))
            .collect::<Vec<_>>();
        let column_proofs = proofs
            .try_into()
            .expect("column proofs should have length of CELLS_PER_EXT_BLOB");

        result.push((column_cells, column_proofs));
    }

    Ok(result)
}

fn try_convert_to_cell(cell: &CKzgCell) -> Result<Cell> {
    ContiguousVector::try_from_iter(cell.to_bytes())
        .map(ByteVector::from)
        .map(Cell::from)
        .map_err(Into::into)
}

pub fn construct_cells_and_kzg_proofs(
    full_matrix: Vec<MatrixEntry>,
    blob_count: usize,
) -> Result<CellsAndKzgProofs> {
    let default_cell = Cell::default();
    let mut cells_and_kzg_proofs = vec![
        (
            core::array::from_fn(|_| default_cell.clone()),
            [KzgProof::zero(); CELLS_PER_EXT_BLOB],
        );
        blob_count
    ];
    for entry in full_matrix {
        let MatrixEntry {
            cell,
            kzg_proof,
            column_index,
            row_index,
        } = entry;

        let row_index = usize::try_from(row_index)?;
        let column_index = usize::try_from(column_index)?;
        cells_and_kzg_proofs[row_index].0[column_index] = cell;
        cells_and_kzg_proofs[row_index].1[column_index] = kzg_proof;
    }

    Ok(cells_and_kzg_proofs)
}
