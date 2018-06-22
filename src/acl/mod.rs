mod ace;

use std::marker::PhantomData;

use winapi::um::winnt::{ACE_HEADER, ACL, PACE_HEADER, PACL};

pub use self::ace::AccessControlEntryPtr;

pub struct AccessControlListPtr<'a> {
    acl: PACL,
    _ptr_lifetime: PhantomData<&'a ()>,
}

impl<'a> AccessControlListPtr<'a> {
    pub unsafe fn new(acl: PACL) -> Self {
        AccessControlListPtr {
            acl,
            _ptr_lifetime: PhantomData,
        }
    }

    pub fn num_entries(&self) -> usize {
        unsafe {
            let acl = self.acl as *const ACL;

            (*acl).AceCount as usize
        }
    }
}

pub struct AccessControlEntries<'a> {
    current_entry: *const ACE_HEADER,
    remaining: usize,
    _ptr_lifetime: PhantomData<&'a ()>,
}

impl<'a> AccessControlEntries<'a> {
    pub unsafe fn new(first_entry: PACE_HEADER, count: usize) -> Self {
        AccessControlEntries {
            current_entry: first_entry as *const ACE_HEADER,
            remaining: count,
            _ptr_lifetime: PhantomData,
        }
    }
}
