use std::marker::PhantomData;

use winapi::um::winnt::{self, ACE_HEADER};

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
