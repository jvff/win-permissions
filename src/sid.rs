use std::ffi::CStr;
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;
use std::ptr;

use winapi::shared::sddl::ConvertSidToStringSidA;
use winapi::um::winbase::LocalFree;
use winapi::um::winnt::PSID;

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
