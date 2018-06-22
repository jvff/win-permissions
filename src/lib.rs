#![cfg(windows)]

extern crate winapi;

mod acl;
mod security_descriptor;
mod sid;

pub use acl::AccessControlListPtr;
pub use security_descriptor::SecurityDescriptor;
pub use sid::SecurityIdPtr;
