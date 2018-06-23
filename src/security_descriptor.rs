use winapi::um::winbase::LocalFree;
use winapi::um::winnt::{PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED};

use super::{AccessControlListPtr, SecurityIdPtr};

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

    pub fn dacl<'a>(&'a self) -> Option<AccessControlListPtr<'a>> {
        unsafe {
            let security_descriptor = self.security_descriptor as *const SECURITY_DESCRIPTOR;
            let dacl = (*security_descriptor).Dacl;

            if dacl.is_null() {
                None
            } else {
                Some(AccessControlListPtr::new(dacl))
            }
        }
    }

    pub fn is_dacl_protected(&self) -> bool {
        unsafe {
            let security_descriptor = self.security_descriptor as *const SECURITY_DESCRIPTOR;

            (*security_descriptor).Control & SE_DACL_PROTECTED != 0
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
