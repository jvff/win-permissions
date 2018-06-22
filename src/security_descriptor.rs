use winapi::um::winbase::LocalFree;
use winapi::um::winnt::PSECURITY_DESCRIPTOR;

pub struct SecurityDescriptor {
    security_descriptor: PSECURITY_DESCRIPTOR,
}

impl SecurityDescriptor {
    pub unsafe fn new(security_descriptor: PSECURITY_DESCRIPTOR) -> Self {
        SecurityDescriptor {
            security_descriptor,
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            if !LocalFree(self.security_descriptor as *mut _).is_null() {
                panic!("Failed to deallocate security descriptor");
            }
        }
    }
}
