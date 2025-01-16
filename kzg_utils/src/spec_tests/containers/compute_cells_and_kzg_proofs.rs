#![expect(clippy::string_slice)]

use serde::Deserialize;
use typenum::Unsigned as _;
use types::{deneb::primitives::KzgProof, fulu::consts::BytesPerCell};

#[derive(Deserialize)]
pub struct Input {
    pub blob: String,
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    pub output: Option<(Vec<String>, Vec<String>)>,
}

impl Test {
    pub fn get_output(&self) -> Option<(Vec<[u8; BytesPerCell::USIZE]>, Vec<KzgProof>)> {
        self.output.as_ref().map(|(cells_str, proofs_str)| {
            let cells = cells_str
                .iter()
                .map(|cell| {
                    let bytes = hex::decode(&cell[2..]).expect("should decode cell bytes");
                    bytes
                        .try_into()
                        .expect("test output cell bytes should fit into BYTES_PER_CELL bytes")
                })
                .collect::<Vec<_>>();

            let proofs = proofs_str
                .iter()
                .map(|proof| {
                    serde_yaml::from_str(proof).expect("should deserialize test output to proof")
                })
                .collect::<Vec<_>>();

            (cells, proofs)
        })
    }
}
