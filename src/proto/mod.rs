//! The protocol library: the "ammunition" core.
//!
//! [`ParsedFrame`] gives offset-checked access to L2 through L4 of one frame
//! and recomputes checksums. [`SeededMapper`] provides the capture-wide,
//! seeded, consistent identifier remap. Each protocol implements [`OtMutator`]
//! (the mutators land in a later phase).

pub mod frame;
pub mod mapper;

pub use frame::{FrameLayout, L3Kind, L4Kind, ParsedFrame};
pub use mapper::{Domain, SeededMapper};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Modbus,
    Enip,
    S7,
    Dnp3,
}

/// One identifier rewrite, recorded for the round's manifest.
#[derive(Clone, Debug)]
pub struct MutationReport {
    pub protocol: Protocol,
    pub field: String,
    pub original: u64,
    pub new: u64,
}

/// A per-protocol payload mutator. Implementations mutate only fixed-width
/// identity fields in the app-layer payload (and their own protocol CRC, if
/// any). The reload pipeline recomputes the L3 and L4 checksums after dispatch,
/// so mutators never touch those.
pub trait OtMutator {
    fn protocol(&self) -> Protocol;
    /// Cheap check that this frame's payload is this protocol.
    fn matches(&self, frame: &ParsedFrame) -> bool;
    /// Rewrite identity fields in place, returning what changed.
    fn mutate(&self, frame: &mut ParsedFrame, mapper: &mut SeededMapper) -> Vec<MutationReport>;
}
