use winapi::um::winbase::LocalFree;
use winapi::um::winnt::{PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED};

use super::{AccessControlList, AccessControlListPtr, SecurityIdPtr};

enum InternalAclPtr {
    PartOfDescriptor(AccessControlListPtr<'static>),
    ExternallyProvided(AccessControlList),
}

pub struct SecurityDescriptor {
    security_descriptor: PSECURITY_DESCRIPTOR,
    dacl: Option<InternalAclPtr>,
}

impl SecurityDescriptor {
    pub unsafe fn new(security_descriptor: PSECURITY_DESCRIPTOR) -> Self {
        let dacl = Self::extract_dacl(security_descriptor as *const SECURITY_DESCRIPTOR);

        SecurityDescriptor {
            security_descriptor,
            dacl,
        }
    }

    unsafe fn extract_dacl(
        security_descriptor: *const SECURITY_DESCRIPTOR,
    ) -> Option<InternalAclPtr> {
        let security_descriptor = security_descriptor as *const SECURITY_DESCRIPTOR;
        let dacl = (*security_descriptor).Dacl;

        if dacl.is_null() {
            None
        } else {
            Some(InternalAclPtr::PartOfDescriptor(AccessControlListPtr::new(
                dacl,
            )))
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
        match self.dacl {
            Some(InternalAclPtr::PartOfDescriptor(ref acl)) => unsafe {
                Some(AccessControlListPtr::new(acl.as_ptr()))
            },
            Some(InternalAclPtr::ExternallyProvided(ref acl)) => unsafe {
                Some(AccessControlListPtr::new(acl.as_ptr()))
            },
            None => None,
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
