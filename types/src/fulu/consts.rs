use typenum::{Prod, U128, U64};

use crate::deneb::consts::BytesPerFieldElement;

// TODO(feature/fulu): make it configurable
pub type NumberOfColumns = U128;
type FieldElementsPerCell = U64;
pub type BytesPerCell = Prod<BytesPerFieldElement, FieldElementsPerCell>;
