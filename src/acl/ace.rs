use std::marker::PhantomData;

use winapi::um::winnt::{self, ACE_HEADER};

pub struct AccessControlEntryPtr<'a> {
    ace: AcePtr,
    _ptr_lifetime: PhantomData<&'a ()>,
}

enum AcePtr {
    AccessAllowed(*const winnt::ACCESS_ALLOWED_ACE),
    Unknown(*const ACE_HEADER),
}

impl<'a> AccessControlEntryPtr<'a> {
    pub unsafe fn new(ace_ptr: *const ACE_HEADER) -> Self {
        use self::AcePtr::*;

        let ace = match (*ace_ptr).AceType {
            winnt::ACCESS_ALLOWED_ACE_TYPE => {
                AccessAllowed(ace_ptr as *const winnt::ACCESS_ALLOWED_ACE)
            }
            _ => Unknown(ace_ptr),
        };

        AccessControlEntryPtr {
            ace,
            _ptr_lifetime: PhantomData,
        }
    }

    pub fn size(&self) -> usize {
        use self::AcePtr::*;

        unsafe {
            let header = match self.ace {
                AccessAllowed(ace) => &(*ace).Header,
                Unknown(ace_header) => &(*ace_header),
            };

            header.AceSize as usize
        }
    }
}
