mod ace;

use std::marker::PhantomData;

use winapi::um::winnt::{ACL, PACL};

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
