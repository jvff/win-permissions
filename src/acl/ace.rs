use std::marker::PhantomData;

use winapi::um::winnt::ACE_HEADER;

pub struct AccessControlEntryPtr<'a> {
    ace: AcePtr,
    _ptr_lifetime: PhantomData<&'a ()>,
}

enum AcePtr {
    Unknown(*const ACE_HEADER),
}

impl<'a> AccessControlEntryPtr<'a> {
    pub unsafe fn new(ace_ptr: *const ACE_HEADER) -> Self {
        AccessControlEntryPtr {
            ace: AcePtr::Unknown(ace_ptr),
            _ptr_lifetime: PhantomData,
        }
    }
}
