use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub fn path_to_cstring(path: &Path) -> Result<CString, ()> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| ())
}
