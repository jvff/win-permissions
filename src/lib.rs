#![cfg(windows)]

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate failure;
extern crate winapi;

mod acl;
mod security_descriptor;
mod sid;

use std::borrow::Borrow;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use winapi::shared::minwindef::DWORD;
use winapi::shared::winerror::ERROR_SUCCESS;
use winapi::um::accctrl::SE_FILE_OBJECT;
use winapi::um::aclapi::{GetNamedSecurityInfoW, SetNamedSecurityInfoW};
use winapi::um::winnt::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};

pub use failure::ResultExt;

pub use acl::{
    AccessControlEntryPtr, AccessControlList, AccessControlListPtr, AccessControlListPtrMut,
    AccessMask, CreateAclError,
};
pub use security_descriptor::SecurityDescriptor;
pub use sid::SecurityIdPtr;

#[derive(Debug, Fail)]
#[fail(display = "Failed to get security information. Error code: {}", win_error_code)]
pub struct GetSecurityInformationError {
    win_error_code: DWORD,
}

#[derive(Debug, Fail)]
#[fail(
    display = "Failed to set the discretionary access control list. Error code: {}", win_error_code
)]
pub struct SetDaclError {
    win_error_code: DWORD,
}

pub trait PathExt {
    fn security_information(&self) -> Result<SecurityDescriptor, GetSecurityInformationError>;
    fn set_dacl<'a, A>(&self, dacl: A) -> Result<(), SetDaclError>
    where
        A: Borrow<AccessControlListPtr<'a>>;
}

impl<T> PathExt for T
where
    T: AsRef<Path>,
{
    fn security_information(&self) -> Result<SecurityDescriptor, GetSecurityInformationError> {
        let mut security_descriptor = ptr::null_mut();

        let file_path: Vec<u16> = self
            .as_ref()
            .as_os_str()
            .encode_wide()
            .chain(once(0))
            .collect();

        unsafe {
            let get_security_info_result = GetNamedSecurityInfoW(
                file_path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut security_descriptor,
            );

            if get_security_info_result != ERROR_SUCCESS {
                return Err(GetSecurityInformationError {
                    win_error_code: get_security_info_result,
                });
            }

            Ok(SecurityDescriptor::new(security_descriptor))
        }
    }

    fn set_dacl<'a, A>(&self, dacl: A) -> Result<(), SetDaclError>
    where
        A: Borrow<AccessControlListPtr<'a>>,
    {
        let mut file_path: Vec<u16> = self
            .as_ref()
            .as_os_str()
            .encode_wide()
            .chain(once(0))
            .collect();

        unsafe {
            let dacl_ptr = dacl.borrow().as_ptr();

            let result = SetNamedSecurityInfoW(
                file_path.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl_ptr,
                ptr::null_mut(),
            );

            match result {
                ERROR_SUCCESS => Ok(()),
                win_error_code => Err(SetDaclError { win_error_code }),
            }
        }
    }
}
