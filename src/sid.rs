use std::borrow::Borrow;
use std::ffi::CStr;
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;
use std::ops::Deref;
use std::ptr;

use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::sddl::ConvertSidToStringSidA;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::securitybaseapi::{AllocateAndInitializeSid, IsWellKnownSid};
use winapi::um::winbase::LocalFree;
use winapi::um::winnt::{self, PSID, SID_IDENTIFIER_AUTHORITY, WELL_KNOWN_SID_TYPE};

pub struct SecurityIdPtr<'a> {
    sid: PSID,
    _ptr_lifetime: PhantomData<&'a ()>,
}

impl<'a> SecurityIdPtr<'a> {
    pub unsafe fn new(sid: PSID) -> Self {
        SecurityIdPtr {
            sid,
            _ptr_lifetime: PhantomData,
        }
    }

    pub fn is_builtin_administrators(&self) -> bool {
        self.is_well_known(winnt::WinBuiltinAdministratorsSid)
    }

    pub fn is_local_system(&self) -> bool {
        self.is_well_known(winnt::WinLocalSystemSid)
    }

    pub fn is_well_known(&self, well_known_sid_type: WELL_KNOWN_SID_TYPE) -> bool {
        unsafe { IsWellKnownSid(self.sid, well_known_sid_type) != 0 }
    }

    pub unsafe fn as_ptr(&self) -> PSID {
        self.sid
    }
}

impl<'a> Display for SecurityIdPtr<'a> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        unsafe {
            let mut sid_string_ptr = ptr::null_mut();

            let convert_result = ConvertSidToStringSidA(self.sid, &mut sid_string_ptr);
            if convert_result == 0 {
                return Err(fmt::Error);
            }

            let sid_cstr = CStr::from_ptr(sid_string_ptr);
            let sid = sid_cstr.to_string_lossy();

            let fmt_result = formatter.write_str(&sid);

            if !LocalFree(sid_string_ptr as *mut _).is_null() {
                panic!("Failed to deallocate string");
            }

            fmt_result
        }
    }
}

impl<'a> AsRef<SecurityIdPtr<'a>> for SecurityIdPtr<'a> {
    fn as_ref(&self) -> &SecurityIdPtr<'a> {
        self
    }
}

#[derive(Debug, Fail)]
#[fail(display = "Failed to create security ID. Error code: {}", win_error_code)]
pub struct CreateSecurityIdError {
    win_error_code: DWORD,
}

pub struct SecurityId {
    sid: SecurityIdPtr<'static>,
}

impl SecurityId {
    pub fn builtin_administrators() -> Result<Self, CreateSecurityIdError> {
        let sid = unsafe {
            let mut top_level_authority = SID_IDENTIFIER_AUTHORITY {
                Value: winnt::SECURITY_NT_AUTHORITY,
            };

            let mut sid_ptr = ptr::null_mut();

            let result = AllocateAndInitializeSid(
                &mut top_level_authority,
                2,
                winnt::SECURITY_BUILTIN_DOMAIN_RID,
                winnt::DOMAIN_ALIAS_RID_ADMINS,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut sid_ptr,
            );

            if result == FALSE {
                return Err(CreateSecurityIdError {
                    win_error_code: GetLastError(),
                });
            }

            SecurityIdPtr::new(sid_ptr)
        };

        Ok(SecurityId { sid })
    }
}

impl Drop for SecurityId {
    fn drop(&mut self) {
        unsafe {
            if !LocalFree(self.sid.as_ptr() as *mut _).is_null() {
                panic!("Failed to deallocate security ID");
            }
        }
    }
}

impl AsRef<SecurityIdPtr<'static>> for SecurityId {
    fn as_ref(&self) -> &SecurityIdPtr<'static> {
        &self.sid
    }
}

impl Borrow<SecurityIdPtr<'static>> for SecurityId {
    fn borrow(&self) -> &SecurityIdPtr<'static> {
        &self.sid
    }
}

impl Deref for SecurityId {
    type Target = SecurityIdPtr<'static>;

    fn deref(&self) -> &Self::Target {
        &self.sid
    }
}

impl Display for SecurityId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.as_ref().fmt(formatter)
    }
}
