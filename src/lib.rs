#![cfg(windows)]

extern crate winapi;

mod security_descriptor;
mod sid;

pub use security_descriptor::SecurityDescriptor;
pub use sid::SecurityIdPtr;
