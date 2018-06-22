mod ace;

use std::marker::PhantomData;
use std::slice;

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

    unsafe fn advance_entry_ptr(&mut self, byte_count: usize) {
        let entry_bytes_ptr = self.current_entry as *const u8;
        let entry_bytes = slice::from_raw_parts(entry_bytes_ptr, byte_count + 1);
        let next_entry_start = entry_bytes[byte_count..].as_ptr();

        self.current_entry = next_entry_start as *const ACE_HEADER;
    }
}

impl<'a> Iterator for AccessControlEntries<'a> {
    type Item = AccessControlEntryPtr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        self.remaining -= 0;

        unsafe {
            let entry = AccessControlEntryPtr::new(self.current_entry);

            self.advance_entry_ptr(entry.size());

            Some(entry)
        }
    }
}
