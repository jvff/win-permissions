use std::marker::PhantomData;
use std::ptr;

use winapi::shared::minwindef::DWORD;
use winapi::um::accctrl::{self, EXPLICIT_ACCESS_W, TRUSTEE_W};
use winapi::um::winnt::{self, ACE_HEADER, PSID};

use super::super::SecurityIdPtr;

bitflags! {
    pub struct AccessMask: u32 {
        const DELETE = winnt::DELETE;
        const READ_CONTROL = winnt::READ_CONTROL;
        const WRITE_DAC = winnt::WRITE_DAC;
        const WRITE_OWNER = winnt::WRITE_OWNER;
        const SYNCHRONIZE = winnt::SYNCHRONIZE;
        const ACCESS_SYSTEM_SECURITY = winnt::ACCESS_SYSTEM_SECURITY;
        const MAXIMUM_ALLOWED = winnt::MAXIMUM_ALLOWED;
        const GENERIC_ALL = winnt::GENERIC_ALL;
        const GENERIC_EXECUTE = winnt::GENERIC_EXECUTE;
        const GENERIC_WRITE = winnt::GENERIC_WRITE;
        const GENERIC_READ = winnt::GENERIC_READ;
    }
}

bitflags! {
    pub struct AccessInheritance: u32 {
        const CONTAINERS_INHERIT = winnt::CONTAINER_INHERIT_ACE as u32;
        const INHERIT_ONLY = winnt::INHERIT_ONLY_ACE as u32;
        const DONT_PROPAGATE = winnt::NO_PROPAGATE_INHERIT_ACE as u32;
        const OBJECTS_INHERIT = winnt::OBJECT_INHERIT_ACE as u32;

        const CONTAINERS_AND_OBJECTS_INHERIT = accctrl::SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        const NO_INHERITANCE = accctrl::NO_INHERITANCE;
        const ONLY_CONTAINERS_INHERIT = accctrl::SUB_CONTAINERS_ONLY_INHERIT;
        const ONLY_OBJECTS_INHERIT = accctrl::SUB_OBJECTS_ONLY_INHERIT;
    }
}

#[repr(u32)]
pub enum AccessMode {
    NotUsed = 0,
    GrantAccess,
    SetAccess,
    DenyAccess,
    RevokeAccess,
    SetAuditSuccess,
    SetAuditFailure,
}

pub struct AccessControlEntryPtr<'a> {
    ace: AcePtr,
    _ptr_lifetime: PhantomData<&'a ()>,
}

enum AcePtr {
    AccessAllowed(*const winnt::ACCESS_ALLOWED_ACE),
    AccessAllowedCallback(*const winnt::ACCESS_ALLOWED_CALLBACK_ACE),
    AccessAllowedCallbackObject(*const winnt::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE),
    AccessAllowedObject(*const winnt::ACCESS_ALLOWED_OBJECT_ACE),
    AccessDenied(*const winnt::ACCESS_DENIED_ACE),
    AccessDeniedCallback(*const winnt::ACCESS_DENIED_CALLBACK_ACE),
    AccessDeniedCallbackObject(*const winnt::ACCESS_DENIED_CALLBACK_OBJECT_ACE),
    AccessDeniedObject(*const winnt::ACCESS_DENIED_OBJECT_ACE),
    Unknown(*const ACE_HEADER),
}

impl<'a> AccessControlEntryPtr<'a> {
    pub unsafe fn new(ace_ptr: *const ACE_HEADER) -> Self {
        use self::AcePtr::*;

        let ace = match (*ace_ptr).AceType {
            winnt::ACCESS_ALLOWED_ACE_TYPE => {
                AccessAllowed(ace_ptr as *const winnt::ACCESS_ALLOWED_ACE)
            }
            winnt::ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
                AccessAllowedCallback(ace_ptr as *const winnt::ACCESS_ALLOWED_CALLBACK_ACE)
            }
            winnt::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => AccessAllowedCallbackObject(
                ace_ptr as *const winnt::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
            ),
            winnt::ACCESS_ALLOWED_OBJECT_ACE_TYPE => {
                AccessAllowedObject(ace_ptr as *const winnt::ACCESS_ALLOWED_OBJECT_ACE)
            }
            winnt::ACCESS_DENIED_ACE_TYPE => {
                AccessDenied(ace_ptr as *const winnt::ACCESS_DENIED_ACE)
            }
            winnt::ACCESS_DENIED_CALLBACK_ACE_TYPE => {
                AccessDeniedCallback(ace_ptr as *const winnt::ACCESS_DENIED_CALLBACK_ACE)
            }
            winnt::ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => AccessDeniedCallbackObject(
                ace_ptr as *const winnt::ACCESS_DENIED_CALLBACK_OBJECT_ACE,
            ),
            winnt::ACCESS_DENIED_OBJECT_ACE_TYPE => {
                AccessDeniedObject(ace_ptr as *const winnt::ACCESS_DENIED_OBJECT_ACE)
            }
            _ => Unknown(ace_ptr),
        };

        AccessControlEntryPtr {
            ace,
            _ptr_lifetime: PhantomData,
        }
    }

    pub fn access_mask(&self) -> Option<AccessMask> {
        use self::AcePtr::*;

        unsafe {
            let raw_access_mask = match self.ace {
                AccessAllowed(ace) => (*ace).Mask,
                AccessAllowedCallback(ace) => (*ace).Mask,
                AccessAllowedCallbackObject(ace) => (*ace).Mask,
                AccessAllowedObject(ace) => (*ace).Mask,
                AccessDenied(ace) => (*ace).Mask,
                AccessDeniedCallback(ace) => (*ace).Mask,
                AccessDeniedCallbackObject(ace) => (*ace).Mask,
                AccessDeniedObject(ace) => (*ace).Mask,
                Unknown(_) => return None,
            };

            Some(AccessMask::from_bits_truncate(raw_access_mask))
        }
    }

    pub fn grants_access(&self) -> Option<bool> {
        use self::AcePtr::*;

        match self.ace {
            AccessAllowed(_)
            | AccessAllowedCallback(_)
            | AccessAllowedCallbackObject(_)
            | AccessAllowedObject(_) => Some(true),
            AccessDenied(_)
            | AccessDeniedCallback(_)
            | AccessDeniedCallbackObject(_)
            | AccessDeniedObject(_) => Some(false),
            Unknown(_) => None,
        }
    }

    pub fn trustee<'b>(&'b self) -> Option<SecurityIdPtr<'b>> {
        use self::AcePtr::*;

        unsafe {
            let sid_start: *const DWORD = match self.ace {
                AccessAllowed(ace) => &(*ace).SidStart,
                AccessAllowedCallback(ace) => &(*ace).SidStart,
                AccessAllowedCallbackObject(ace) => &(*ace).SidStart,
                AccessAllowedObject(ace) => &(*ace).SidStart,
                AccessDenied(ace) => &(*ace).SidStart,
                AccessDeniedCallback(ace) => &(*ace).SidStart,
                AccessDeniedCallbackObject(ace) => &(*ace).SidStart,
                AccessDeniedObject(ace) => &(*ace).SidStart,
                Unknown(_) => return None,
            };

            Some(SecurityIdPtr::new(sid_start as PSID))
        }
    }

    pub fn size(&self) -> usize {
        use self::AcePtr::*;

        unsafe {
            let header = match self.ace {
                AccessAllowed(ace) => &(*ace).Header,
                AccessAllowedCallback(ace) => &(*ace).Header,
                AccessAllowedCallbackObject(ace) => &(*ace).Header,
                AccessAllowedObject(ace) => &(*ace).Header,
                AccessDenied(ace) => &(*ace).Header,
                AccessDeniedCallback(ace) => &(*ace).Header,
                AccessDeniedCallbackObject(ace) => &(*ace).Header,
                AccessDeniedObject(ace) => &(*ace).Header,
                Unknown(ace_header) => &(*ace_header),
            };

            header.AceSize as usize
        }
    }
}

pub struct ExplicitAccess<'trustee> {
    explicit_access: EXPLICIT_ACCESS_W,
    _trustee_lifetime: PhantomData<&'trustee ()>,
}

impl<'trustee> ExplicitAccess<'trustee> {
    pub fn new<T: AsRef<SecurityIdPtr<'trustee>>>(
        permissions: AccessMask,
        mode: AccessMode,
        inheritance: AccessInheritance,
        trustee: T,
    ) -> Self {
        ExplicitAccess {
            explicit_access: EXPLICIT_ACCESS_W {
                grfAccessPermissions: permissions.bits(),
                grfAccessMode: mode as u32,
                grfInheritance: inheritance.bits(),
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: ptr::null_mut(),
                    MultipleTrusteeOperation: accctrl::NO_MULTIPLE_TRUSTEE,
                    TrusteeForm: accctrl::TRUSTEE_IS_SID,
                    TrusteeType: accctrl::TRUSTEE_IS_UNKNOWN,
                    ptstrName: unsafe { trustee.as_ref().as_ptr() as *mut _ },
                },
            },
            _trustee_lifetime: PhantomData,
        }
    }
}
