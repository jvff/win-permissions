use std::marker::PhantomData;

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
