//! The per-protocol mutators and a registry over them.

pub mod dnp3;
pub mod enip;
pub mod modbus;
pub mod s7comm;

use super::{OtMutator, Protocol};

/// Every mutator, in dispatch order. The first whose `matches` returns true
/// handles a frame.
pub fn all() -> Vec<Box<dyn OtMutator>> {
    vec![
        Box::new(modbus::Modbus),
        Box::new(enip::Enip),
        Box::new(s7comm::S7),
        Box::new(dnp3::Dnp3),
    ]
}

/// The mutator set for a chosen protocol, or all of them.
pub fn for_protocol(p: Option<Protocol>) -> Vec<Box<dyn OtMutator>> {
    match p {
        None => all(),
        Some(want) => all().into_iter().filter(|m| m.protocol() == want).collect(),
    }
}
