#![expect(clippy::manual_let_else)]

use anyhow::Result;
use c_kzg::{Blob, Bytes48, Cell, KzgProof};
use duplicate::duplicate_item;
use serde::Deserialize;
use spec_test_utils::Case;
use test_generator::test_resources;
use types::{
    fulu::primitives::{ColumnIndex, CustodyIndex},
    nonstandard::Phase,
    phase0::primitives::NodeId,
    preset::{Mainnet, Minimal, Preset},
};

use crate::{compute_columns_for_custody_group, get_custody_groups, trusted_setup::settings};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetCustodyGroupsMeta {
    node_id: NodeId,
    custody_group_count: u64,
    result: Vec<CustodyIndex>,
}

#[duplicate_item(
    glob                                                                           function_name                preset;
    ["consensus-spec-tests/tests/mainnet/fulu/networking/get_custody_groups/*/*"] [get_custody_groups_mainnet] [Mainnet];
    ["consensus-spec-tests/tests/minimal/fulu/networking/get_custody_groups/*/*"] [get_custody_groups_minimal] [Minimal];
)]
#[test_resources(glob)]
fn function_name(case: Case) {
    run_get_custody_groups_case::<preset>(case);
}

fn run_get_custody_groups_case<P: Preset>(case: Case) {
    let GetCustodyGroupsMeta {
        node_id,
        custody_group_count,
        result,
    } = case.yaml("meta");

    let config = P::default_config().start_and_stay_in(Phase::Fulu);
    let custody_groups = get_custody_groups(node_id, custody_group_count, &config)
        .expect("custody groups must be valid");

    assert_eq!(custody_groups.collect::<Vec<_>>(), result);
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComputeColumnsForCustodyGroup {
    custody_group: CustodyIndex,
    result: Vec<ColumnIndex>,
}

#[duplicate_item(
    glob                                                                                         function_name                               preset;
    ["consensus-spec-tests/tests/mainnet/fulu/networking/compute_columns_for_custody_group/*/*"] [compute_columns_for_custody_group_mainnet] [Mainnet];
    ["consensus-spec-tests/tests/minimal/fulu/networking/compute_columns_for_custody_group/*/*"] [compute_columns_for_custody_group_minimal] [Minimal];
)]
#[test_resources(glob)]
fn function_name(case: Case) {
    run_compute_columns_for_custody_group::<preset>(case);
}

fn run_compute_columns_for_custody_group<P: Preset>(case: Case) {
    let ComputeColumnsForCustodyGroup {
        custody_group,
        result,
    } = case.yaml("meta");

    let config = P::default_config().start_and_stay_in(Phase::Fulu);
    let columns = compute_columns_for_custody_group(custody_group, &config)
        .expect("custody group must be valid");

    assert_eq!(columns.collect::<Vec<_>>(), result);
}

type CellsKzgProofsOption = Option<(Result<Vec<Cell>>, Result<Vec<Bytes48>>)>;

#[derive(Deserialize)]
struct ComputeCellsKzgProofsInput {
    blob: String,
}

#[derive(Deserialize)]
struct ComputeCellsKzgProofsTest {
    input: ComputeCellsKzgProofsInput,
    output: Option<(Vec<String>, Vec<String>)>,
}

impl ComputeCellsKzgProofsTest {
    fn get_output(&self) -> CellsKzgProofsOption {
        self.output.clone().map(|(cells, proofs)| {
            (
                cells
                    .iter()
                    .map(|s| Cell::from_hex(s).map_err(Into::into))
                    .collect::<Result<Vec<Cell>>>(),
                proofs
                    .iter()
                    .map(|s| Bytes48::from_hex(s).map_err(Into::into))
                    .collect::<Result<Vec<Bytes48>>>(),
            )
        })
    }
}

#[test_resources("consensus-spec-tests/tests/general/fulu/kzg/compute_cells_and_kzg_proofs/*/*")]
fn test_compute_cells_and_kzg_proofs(case: Case) {
    let test = case.yaml::<ComputeCellsKzgProofsTest>("data");

    let blob = match Blob::from_hex(&test.input.blob) {
        Ok(blob) => blob,
        Err(_) => {
            assert!(test.output.is_none());
            return;
        }
    };

    match Cell::compute_cells_and_kzg_proofs(&blob, settings()) {
        Ok((cells, proofs)) => {
            let output = test.get_output().expect("test output should exist");
            let expected_cells = output.0.expect("cells should be valid");
            let expected_proofs = output.1.expect("proofs should be valid");

            assert_eq!(cells.to_vec(), expected_cells);
            assert_eq!(
                proofs.map(|p| KzgProof::to_bytes(&p)).to_vec(),
                expected_proofs
            );
        }
        Err(_) => {
            assert!(test.output.is_none());
        }
    }
}

#[derive(Deserialize)]
struct RecoverCellsKzgProofsInput {
    cell_indices: Vec<u64>,
    cells: Vec<String>,
}

impl RecoverCellsKzgProofsInput {
    fn get_cells(&self) -> Result<Vec<Cell>> {
        self.cells
            .iter()
            .map(|c| Cell::from_hex(c).map_err(Into::into))
            .collect::<Result<Vec<Cell>>>()
    }
}

#[derive(Deserialize)]
struct RecoverCellsKzgProofsTest {
    input: RecoverCellsKzgProofsInput,
    output: Option<(Vec<String>, Vec<String>)>,
}

impl RecoverCellsKzgProofsTest {
    fn get_output(&self) -> CellsKzgProofsOption {
        self.output.clone().map(|(cells, proofs)| {
            (
                cells
                    .iter()
                    .map(|s| Cell::from_hex(s).map_err(Into::into))
                    .collect::<Result<Vec<Cell>>>(),
                proofs
                    .iter()
                    .map(|s| Bytes48::from_hex(s).map_err(Into::into))
                    .collect::<Result<Vec<Bytes48>>>(),
            )
        })
    }
}

#[test_resources("consensus-spec-tests/tests/general/fulu/kzg/recover_cells_and_kzg_proofs/*/*")]
fn test_recover_cells_and_kzg_proofs(case: Case) {
    let test = case.yaml::<RecoverCellsKzgProofsTest>("data");

    let cells = match test.input.get_cells() {
        Ok(cells) => cells,
        Err(_) => {
            assert!(test.output.is_none());
            return;
        }
    };

    match Cell::recover_cells_and_kzg_proofs(&test.input.cell_indices, &cells, settings()) {
        Ok((cells, proofs)) => {
            let output = test.get_output().expect("test output should exist");
            let expected_cells = output.0.expect("cells should be valid");
            let expected_proofs = output.1.expect("proofs should be valid");

            assert_eq!(cells.to_vec(), expected_cells);
            assert_eq!(
                proofs.map(|p| KzgProof::to_bytes(&p)).to_vec(),
                expected_proofs
            );
        }
        Err(_) => {
            assert!(test.output.is_none());
        }
    }
}

#[derive(Deserialize)]
struct VerifyKzgProofBatchInput {
    commitments: Vec<String>,
    cell_indices: Vec<u64>,
    cells: Vec<String>,
    proofs: Vec<String>,
}

impl VerifyKzgProofBatchInput {
    fn get_commitments(&self) -> Result<Vec<Bytes48>> {
        self.commitments
            .iter()
            .map(|s| Bytes48::from_hex(s).map_err(Into::into))
            .collect::<Result<Vec<Bytes48>>>()
    }

    fn get_cells(&self) -> Result<Vec<Cell>> {
        self.cells
            .iter()
            .map(|s| Cell::from_hex(s).map_err(Into::into))
            .collect::<Result<Vec<Cell>>>()
    }

    fn get_proofs(&self) -> Result<Vec<Bytes48>> {
        self.proofs
            .iter()
            .map(|s| Bytes48::from_hex(s).map_err(Into::into))
            .collect::<Result<Vec<Bytes48>>>()
    }
}

#[derive(Deserialize)]
struct VerifyKzgProofBatchTest {
    input: VerifyKzgProofBatchInput,
    output: Option<bool>,
}

#[test_resources("consensus-spec-tests/tests/general/fulu/kzg/verify_cell_kzg_proof_batch/*/*")]
fn test_verify_cell_kzg_proof_batch(case: Case) {
    let test = case.yaml::<VerifyKzgProofBatchTest>("data");

    let commitments = match test.input.get_commitments() {
        Ok(c) => c,
        Err(_) => {
            assert!(test.output.is_none());
            return;
        }
    };

    let cells = match test.input.get_cells() {
        Ok(cells) => cells,
        Err(_) => {
            assert!(test.output.is_none());
            return;
        }
    };

    let proofs = match test.input.get_proofs() {
        Ok(proofs) => proofs,
        Err(_) => {
            assert!(test.output.is_none());
            return;
        }
    };

    match KzgProof::verify_cell_kzg_proof_batch(
        &commitments,
        &test.input.cell_indices,
        &cells,
        &proofs,
        settings(),
    ) {
        Ok(output) => {
            let expected_output = test.output.expect("test output should exist");

            assert_eq!(output, expected_output);
        }
        Err(_) => {
            assert!(test.output.is_none());
        }
    }
}
