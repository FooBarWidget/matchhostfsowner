use failure::Fail;
use libc;
use libc::{c_char, c_int, ssize_t};
use nix::unistd::Gid;
use std::ffi::CStr;
use std::option::Option;
use std::result::Result;

pub struct OsGroup {
    pub name: String,
}

#[derive(Debug, Fail)]
#[fail(display = "{}", msg)]
pub struct Error {
    msg: String,
    code: c_int,
}

impl OsGroup {
    pub fn from_gid(gid: &Gid) -> Result<Option<OsGroup>, Error> {
        // _SC_GETPW_R_SIZE_MAX is not a maximum:
        // http://tomlee.co/2012/10/problems-with-large-linux-unix-groups-and-getgrgid_r-getgrnam_r/
        let buffer_size = OsGroup::get_buffer_size();
        let buffer = CBuffer::new(buffer_size);
        let mut group_struct: libc::group = unsafe { std::mem::uninitialized() };
        let mut output = std::ptr::null_mut::<libc::group>();

        let code = unsafe {
            libc::getgrgid_r(
                gid.as_raw() as libc::gid_t,
                &mut group_struct,
                buffer.ptr,
                buffer.size,
                &mut output,
            )
        };
        if code == 0 {
            if output.is_null() {
                Ok(None)
            } else {
                Ok(Some(OsGroup {
                    name: OsGroup::c_char_to_string(group_struct.gr_name),
                }))
            }
        } else {
            let msg = unsafe { OsGroup::c_char_to_string(libc::strerror(code)) };
            Err(Error {
                msg: msg,
                code: code,
            })
        }
    }

    fn get_buffer_size() -> usize {
        // _SC_GETGR_R_SIZE_MAX is not a maximum:
        // http://tomlee.co/2012/10/problems-with-large-linux-unix-groups-and-getgrgid_r-getgrnam_r/
        let getgr_r_size_max = unsafe { libc::sysconf(libc::_SC_GETGR_R_SIZE_MAX) };
        ((1024 * 128) as ssize_t).max(getgr_r_size_max as ssize_t) as usize
    }

    fn c_char_to_string(ptr: *const c_char) -> String {
        unsafe { CStr::from_ptr(ptr).to_string_lossy().to_string() }
    }
}

struct CBuffer {
    ptr: *mut c_char,
    size: usize,
}

impl CBuffer {
    fn new(size: usize) -> CBuffer {
        let mut raw_buffer = Vec::<c_char>::with_capacity(size);
        let ptr = raw_buffer.as_mut_ptr();
        std::mem::forget(raw_buffer);
        CBuffer {
            ptr: ptr,
            size: size,
        }
    }
}

impl Drop for CBuffer {
    fn drop(&mut self) {
        unsafe {
            std::mem::drop(Vec::from_raw_parts(self.ptr, 0, self.size));
        }
    }
}
