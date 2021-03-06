mod ace;

use std::borrow::Borrow;
use std::marker::PhantomData;
use std::ops::Deref;
use std::{mem, ptr, slice};

use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::winerror::ERROR_SUCCESS;
use winapi::um::accctrl::PEXPLICIT_ACCESS_W;
use winapi::um::aclapi::SetEntriesInAclW;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::minwinbase::LPTR;
use winapi::um::securitybaseapi::InitializeAcl;
use winapi::um::winbase::{LocalAlloc, LocalFree};
use winapi::um::winnt::{ACE_HEADER, ACL, ACL_REVISION, PACE_HEADER, PACL};

pub use self::ace::{
    AccessControlEntryPtr, AccessInheritance, AccessMask, AccessMode, ExplicitAccess,
};

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

    pub fn entries<'b>(&'b self) -> AccessControlEntries<'b> {
        unsafe {
            let acl_ptr = self.acl as *const ACL;
            let acl = slice::from_raw_parts(acl_ptr, 2);
            let first_entry_ptr = acl[2..].as_ptr() as PACE_HEADER;

            AccessControlEntries::new(first_entry_ptr, self.num_entries())
        }
    }

    pub unsafe fn as_ptr(&self) -> PACL {
        self.acl
    }

    pub fn try_to_owned(&self) -> Result<AccessControlList, CreateAclError> {
        AccessControlList::clone_from(self)
    }
}

impl<'a> AsRef<AccessControlListPtr<'a>> for AccessControlListPtr<'a> {
    fn as_ref(&self) -> &AccessControlListPtr<'a> {
        self
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

pub struct AccessControlListPtrMut<'a> {
    acl: AccessControlListPtr<'a>,
}

impl<'a> AccessControlListPtrMut<'a> {
    pub unsafe fn new(acl: PACL) -> Self {
        AccessControlListPtrMut {
            acl: AccessControlListPtr::new(acl),
        }
    }
}

impl<'a> AsRef<AccessControlListPtr<'a>> for AccessControlListPtrMut<'a> {
    fn as_ref(&self) -> &AccessControlListPtr<'a> {
        &self.acl
    }
}

impl<'a> Borrow<AccessControlListPtr<'a>> for AccessControlListPtrMut<'a> {
    fn borrow(&self) -> &AccessControlListPtr<'a> {
        &self.acl
    }
}

impl<'a> Deref for AccessControlListPtrMut<'a> {
    type Target = AccessControlListPtr<'a>;

    fn deref(&self) -> &Self::Target {
        &self.acl
    }
}

#[derive(Debug, Fail)]
#[fail(display = "Failed to create empty access control list. Error code: {}", win_error_code)]
pub struct CreateAclError {
    win_error_code: DWORD,
}

pub struct AccessControlList {
    acl: AccessControlListPtrMut<'static>,
}

impl AccessControlList {
    pub fn new() -> Result<Self, CreateAclError> {
        unsafe {
            let acl_size = mem::size_of::<ACL>();

            let acl_ptr = LocalAlloc(LPTR, acl_size) as PACL;
            if acl_ptr.is_null() {
                return Err(CreateAclError {
                    win_error_code: GetLastError(),
                });
            }

            let init_result = InitializeAcl(acl_ptr, acl_size as u32, ACL_REVISION as u32);
            if init_result == FALSE {
                return Err(CreateAclError {
                    win_error_code: GetLastError(),
                });
            }

            let acl = AccessControlListPtrMut::new(acl_ptr);

            Ok(AccessControlList { acl })
        }
    }

    pub fn clone_from<'a, T>(template_acl: T) -> Result<Self, CreateAclError>
    where
        T: AsRef<AccessControlListPtr<'a>>,
    {
        unsafe { Self::create_acl(template_acl.as_ref().as_ptr(), 0, ptr::null_mut()) }
    }

    pub fn insert<'trustee>(
        &mut self,
        explicit_entry: ExplicitAccess<'trustee>,
    ) -> Result<(), CreateAclError> {
        let updated_acl = unsafe { Self::create_acl(self.as_ptr(), 1, explicit_entry.as_ptr())? };

        mem::replace(self, updated_acl);

        Ok(())
    }

    unsafe fn create_acl(
        template_acl_ptr: PACL,
        extra_entries_count: u32,
        extra_entries_ptr: PEXPLICIT_ACCESS_W,
    ) -> Result<Self, CreateAclError> {
        let mut acl_ptr = ptr::null_mut();

        let result = SetEntriesInAclW(
            extra_entries_count,
            extra_entries_ptr,
            template_acl_ptr,
            &mut acl_ptr,
        );
        if result != ERROR_SUCCESS {
            return Err(CreateAclError {
                win_error_code: result,
            });
        }

        let acl = AccessControlListPtrMut::new(acl_ptr);

        Ok(AccessControlList { acl })
    }
}

impl Drop for AccessControlList {
    fn drop(&mut self) {
        unsafe {
            if !LocalFree(self.acl.as_ptr() as *mut _).is_null() {
                panic!("Failed to deallocate access control list");
            }
        }
    }
}

impl AsRef<AccessControlListPtrMut<'static>> for AccessControlList {
    fn as_ref(&self) -> &AccessControlListPtrMut<'static> {
        &self.acl
    }
}

impl AsRef<AccessControlListPtr<'static>> for AccessControlList {
    fn as_ref(&self) -> &AccessControlListPtr<'static> {
        self.acl.as_ref()
    }
}

impl Borrow<AccessControlListPtrMut<'static>> for AccessControlList {
    fn borrow(&self) -> &AccessControlListPtrMut<'static> {
        &self.acl
    }
}

impl Borrow<AccessControlListPtr<'static>> for AccessControlList {
    fn borrow(&self) -> &AccessControlListPtr<'static> {
        self.acl.as_ref()
    }
}

impl Deref for AccessControlList {
    type Target = AccessControlListPtrMut<'static>;

    fn deref(&self) -> &Self::Target {
        &self.acl
    }
}
