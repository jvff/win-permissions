use winapi::um::winbase::LocalFree;
use winapi::um::winnt::{PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR};

use super::SecurityIdPtr;

pub struct SecurityDescriptor {
    security_descriptor: PSECURITY_DESCRIPTOR,
}

impl SecurityDescriptor {
    pub unsafe fn new(security_descriptor: PSECURITY_DESCRIPTOR) -> Self {
        SecurityDescriptor {
            security_descriptor,
        }
    }

    pub fn owner<'a>(&'a self) -> Option<SecurityIdPtr<'a>> {
        unsafe {
            let security_descriptor = self.security_descriptor as *const SECURITY_DESCRIPTOR;
            let owner = (*security_descriptor).Owner;

            if owner.is_null() {
                None
            } else {
                Some(SecurityIdPtr::new(owner))
            }
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            if !LocalFree(self.security_descriptor as *mut _).is_null() {
                panic!("Failed to deallocate security descriptor");
            }
        }
    }
}
