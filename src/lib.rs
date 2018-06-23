#![cfg(windows)]

extern crate winapi;

mod acl;
mod security_descriptor;
mod sid;

pub use acl::{AccessControlEntryPtr, AccessControlListPtr, AccessMask};
pub use security_descriptor::SecurityDescriptor;
pub use sid::SecurityIdPtr;
