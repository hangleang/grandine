use anyhow::Result;
use kzg::eth::eip_7594::{
    compute_cells_and_kzg_proofs_raw, compute_cells_raw, recover_cells_and_kzg_proofs_raw,
    verify_cell_kzg_proof_batch_raw,
};
use rust_kzg_blst::eip_7594::BlstBackend;
use ssz::{ByteVector, ContiguousVector};
use try_from_iterator::TryFromIterator;
use types::{
    deneb::primitives::{Blob, KzgCommitment, KzgProof},
    fulu::primitives::{Cell, CellIndex, CellsAndKzgProofs},
    preset::Preset,
};

use crate::{error::KzgError, trusted_setup};

pub fn verify_cell_kzg_proof_batch<'a, P: Preset>(
    commitments: impl IntoIterator<Item = &'a KzgCommitment>,
    cell_indices: impl IntoIterator<Item = CellIndex>,
    cells: impl IntoIterator<Item = &'a Cell<P>>,
    proofs: impl IntoIterator<Item = &'a KzgProof>,
) -> Result<bool> {
    let raw_commitments = commitments
        .into_iter()
        .map(|c| c.to_fixed_bytes())
        .collect::<Vec<_>>();

    let cell_indices = cell_indices
        .into_iter()
        .map(|index| usize::try_from(index).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let raw_cells = cells
        .into_iter()
        .map(|c| c.as_bytes().try_into().map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let raw_proofs = proofs
        .into_iter()
        .map(|p| p.to_fixed_bytes())
        .collect::<Vec<_>>();

    verify_cell_kzg_proof_batch_raw::<BlstBackend>(
        &raw_commitments,
        &cell_indices,
        &raw_cells,
        &raw_proofs,
        trusted_setup::blst_settings(),
    )
    .map_err(KzgError::KzgError)
    .map_err(Into::into)
}

pub fn compute_cells_and_kzg_proofs<P: Preset>(blob: &Blob<P>) -> Result<CellsAndKzgProofs<P>> {
    let raw_blob = blob.as_bytes().try_into()?;

    let (cells, proofs) =
        compute_cells_and_kzg_proofs_raw::<BlstBackend>(raw_blob, trusted_setup::blst_settings())
            .map_err(KzgError::KzgError)?;
    let cells = cells
        .into_iter()
        .map(try_convert_to_cell::<P>)
        .collect::<Result<Vec<_>>>()?;
    let cells = ContiguousVector::try_from_iter(cells)?;
    let proofs = ContiguousVector::try_from_iter(proofs.into_iter().map(Into::into))?;

    Ok((cells, proofs))
}

pub fn recover_cells_and_kzg_proofs<'cell, P: Preset>(
    cell_indices: impl IntoIterator<Item = CellIndex>,
    cells: impl IntoIterator<Item = &'cell Cell<P>>,
) -> Result<CellsAndKzgProofs<P>> {
    let cell_indices = cell_indices
        .into_iter()
        .map(|index| usize::try_from(index).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let raw_cells = cells
        .into_iter()
        .map(|c| c.as_bytes().try_into().map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let (cells, proofs) = recover_cells_and_kzg_proofs_raw::<BlstBackend>(
        &cell_indices,
        &raw_cells,
        trusted_setup::blst_settings(),
    )
    .map_err(KzgError::KzgError)?;

    let cells = cells
        .into_iter()
        .map(try_convert_to_cell::<P>)
        .collect::<Result<Vec<_>>>()?;
    let cells = ContiguousVector::try_from_iter(cells)?;
    let proofs = ContiguousVector::try_from_iter(proofs.into_iter().map(Into::into))?;

    Ok((cells, proofs))
}

pub fn compute_cells<P: Preset>(
    blob: &Blob<P>,
) -> Result<ContiguousVector<Cell<P>, P::CellsPerExtBlob>> {
    let raw_blob = blob.as_bytes().try_into()?;

    let cells = compute_cells_raw::<BlstBackend>(raw_blob, trusted_setup::blst_settings())
        .map_err(KzgError::KzgError)?;
    let cells = cells
        .into_iter()
        .map(try_convert_to_cell::<P>)
        .collect::<Result<Vec<_>>>()?;

    ContiguousVector::try_from_iter(cells).map_err(Into::into)
}

pub(crate) fn try_convert_to_cell<P: Preset>(
    cell: impl IntoIterator<Item = u8>,
) -> Result<Cell<P>> {
    ContiguousVector::try_from_iter(cell)
        .map(ByteVector::from)
        .map(Cell::<P>::from)
        .map_err(Into::into)
}
