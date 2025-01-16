use anyhow::Result;
use kzg::eth::eip_7594::{
    compute_cells_and_kzg_proofs_raw, recover_cells_and_kzg_proofs_raw,
    verify_cell_kzg_proof_batch_raw,
};
use rust_kzg_blst::eip_7594::BlstBackend;
use typenum::Unsigned as _;
use types::{
    deneb::primitives::{Blob, KzgCommitment, KzgProof},
    fulu::{
        consts::BytesPerCell,
        primitives::{Cell, CellIndex},
    },
    preset::Preset,
};

use crate::{error::KzgError, trusted_setup::settings};

pub fn verify_cell_kzg_proof_batch<'a>(
    commitments: impl IntoIterator<Item = &'a KzgCommitment>,
    cell_indices: impl IntoIterator<Item = CellIndex>,
    cells: impl IntoIterator<Item = &'a Cell>,
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
        settings(),
    )
    .map_err(KzgError::KzgError)
    .map_err(Into::into)
}

pub fn compute_cells_and_kzg_proofs<P: Preset>(
    blob: &Blob<P>,
) -> Result<(
    impl IntoIterator<Item = [u8; BytesPerCell::USIZE]>,
    impl IntoIterator<Item = KzgProof>,
)> {
    let raw_blob = blob.as_bytes().try_into()?;

    let (cells, proofs) = compute_cells_and_kzg_proofs_raw::<BlstBackend>(raw_blob, settings())
        .map_err(KzgError::KzgError)?;

    Ok((cells, proofs.into_iter().map(Into::into)))
}

pub fn recover_cells_and_kzg_proofs(
    cell_indices: impl IntoIterator<Item = CellIndex>,
    cells: impl IntoIterator<Item = Cell>,
) -> Result<(
    impl IntoIterator<Item = [u8; BytesPerCell::USIZE]>,
    impl IntoIterator<Item = KzgProof>,
)> {
    let cell_indices = cell_indices
        .into_iter()
        .map(|index| usize::try_from(index).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let raw_cells = cells
        .into_iter()
        .map(|c| c.as_bytes().try_into().map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let (cells, proofs) =
        recover_cells_and_kzg_proofs_raw::<BlstBackend>(&cell_indices, &raw_cells, settings())
            .map_err(KzgError::KzgError)?;

    Ok((cells, proofs.into_iter().map(Into::into)))
}
