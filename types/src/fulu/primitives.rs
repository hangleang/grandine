use ssz::{ByteVector, ContiguousVector};

use crate::{fulu::consts::BytesPerCell, phase0::primitives::H256, preset::Preset};

pub type RowIndex = u64;
pub type CellIndex = u64;
pub type ColumnIndex = u64;
pub type CustodyIndex = u64;
pub type Cell = Box<ByteVector<BytesPerCell>>;
pub type BlobCommitmentsInclusionProof<P> =
    ContiguousVector<H256, <P as Preset>::KzgCommitmentsInclusionProofDepth>;
