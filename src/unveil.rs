use std::error::Error as StdError;
use std::path::Path;

#[cfg(target_os = "openbsd")]
mod openbsd_ext {
    use crate::util::path_to_cstring;
    use std::ffi::CString;
    use std::io;
    use std::path::Path;

    pub(super) fn unveil<P: AsRef<Path>>(path: P, permissions: &str) -> crate::Result<()> {
        let p = path_to_cstring(path.as_ref()).map_err(|_| crate::Error::PathContainsNul)?;

        let r = CString::new(permissions)
            .expect("invariant violated: permissions value could not be converted to CString");

        let result = unsafe { libc::unveil(p.as_ptr(), r.as_ptr()) };

        if result == 0 {
            Ok(())
        } else {
            Err(crate::Error::Unveil(io::Error::last_os_error()))
        }
    }

    pub(super) fn unveil_finalize() -> crate::Result<()> {
        let r = unsafe { libc::unveil(std::ptr::null(), std::ptr::null()) };

        if r == 0 {
            Ok(())
        } else {
            Err(crate::Error::Unveil(io::Error::last_os_error()))
        }
    }
}

///
/// This is a permissions type for the `unveil` system call.
/// This exists for type safety and to make it extremely obvious what
/// permissions are being asserted for a path.
///
/// Permissions can be combined with the `|` (`BitOr`) operator.
///
/// # Example
///
/// ```rust
/// use obsd_guard::UnveilPermissions;
///
/// let perms = UnveilPermissions::READ
///     | UnveilPermissions::CREATE
///     | UnveilPermissions::WRITE;
///
/// assert_eq!(perms.as_str(), "rwc");
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct UnveilPermissions(u8);

impl UnveilPermissions {
    /// Read permission
    pub const READ: Self = Self(0b0001);

    /// Write permission
    pub const WRITE: Self = Self(0b0010);

    /// Execute permission
    pub const EXECUTE: Self = Self(0b0100);

    /// Create permission
    pub const CREATE: Self = Self(0b1000);

    /// No permission (⊥)
    pub const NONE: Self = Self(0);

    pub fn as_str(self) -> &'static str {
        match self.0 {
            //cxwr
            0b0000 => "",
            0b0001 => "r",
            0b0010 => "w",
            0b0011 => "rw",
            0b0100 => "x",
            0b0101 => "rx",
            0b0110 => "wx",
            0b0111 => "rwx",
            0b1000 => "c",
            0b1001 => "rc",
            0b1010 => "wc",
            0b1011 => "rwc",
            0b1100 => "xc",
            0b1101 => "rxc",
            0b1110 => "wxc",
            0b1111 => "rwxc",
            _ => unreachable!(),
        }
    }
}

impl std::ops::BitOr for UnveilPermissions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for UnveilPermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

///
/// The structure used to proxy calls to the OpenBSD `unveil(2)` system call.
///
/// This cannot be initialized publicly.
/// It should only be used in the lambda passed into a `with_unveil` call.
pub struct UnveilBuilder {
    /// This is to prevent initialization outside of this module.
    _private: (),
}

impl UnveilBuilder {
    ///
    /// Restricts the visibility of the filesystem for the current process to
    /// the specified path with the given permissions. This function uses
    /// the OpenBSD `unveil(2)` system call.
    ///
    /// Once `unveil` is called, the process will only be able to access files
    /// or directories explicitly allowed through previous `unveil` calls.
    ///
    /// # Arguments
    ///
    /// * `path` - A reference to a `Path` that specifies the directory or file
    ///   to unveil.
    /// * `permissions` - An [`UnveilPermissions`] value specifying the allowed
    ///   permissions.
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success.
    /// * An `Err` variant of `obsd_guard::Error` if the unveiling process
    ///   fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::path::Path;
    /// use obsd_guard::{UnveilPermissions, with_unveil};
    ///
    /// let result = with_unveil(|u| {
    ///     // Only read from a directory.
    ///     u.unveil(Path::new("/path/to/directory"), UnveilPermissions::READ)?;
    ///     // Block access to a specific subdirectory of the previous one
    ///     // to which we allowed read access.
    ///     u.unveil(Path::new("/path/to/directory/sensitive_info"), UnveilPermissions::NONE)?;
    ///
    ///     // We want the permission to read, write, and create a service configuration file.
    ///     u.unveil(
    ///         Path::new("/etc/myservice.conf"),
    ///         UnveilPermissions::READ
    ///         | UnveilPermissions::CREATE
    ///         | UnveilPermissions::WRITE
    ///     )
    /// });
    /// ```
    ///
    /// # Errors
    ///
    /// This function returns an error if:
    /// * The `unveil` system call fails (see: https://man.openbsd.org/unveil.2)
    /// * The specified path or permissions cannot be transformed into
    ///   C-strings.
    pub fn unveil<P: AsRef<Path>>(
        &mut self,
        path: P,
        permissions: UnveilPermissions,
    ) -> crate::error::Result<()> {
        openbsd_ext::unveil(path, permissions.as_str())
    }

    ///
    /// Invokes the OpenBSD `unveil(2)` system call with both parameters `NULL`
    /// to finalize filesystem permissions, making them permanently
    /// immutable thereafter.
    ///
    /// # Errors
    ///
    /// Results in an error if the system call fails.
    fn finalize(&self) -> crate::error::Result<()> {
        openbsd_ext::unveil_finalize()
    }
}

///
/// This function exists to force proper use of the OpenBSD `unveil(2)` system
/// call.
///
/// See the example below for how this is achieved.
///
/// # Example
///
/// ```rust
/// use obsd_guard::{error, with_unveil , UnveilPermissions};
/// use std::path::Path;
///
/// fn init_sandbox() -> error::Result<()> {
///     with_unveil(|u| {
///         u.unveil(
///             "/etc/myservice.conf",
///             UnveilPermissions::CREATE
///             | UnveilPermissions::READ
///             | UnveilPermissions::WRITE
///         )?;
///
///         u.unveil(Path::new("/root/mything.log"), UnveilPermissions::WRITE)
///     })
///     // At this point, unveil(NULL, NULL) has been called,
///     //  and permissions are immutable for the rest of the process lifetime.
///     //  The kernel will deny any further calls to unveil.
/// }
///
/// fn main() {
///     init_sandbox()
///         .expect("Sandbox initialization failed.");
/// }
/// ```
pub fn with_unveil<F, T>(f: F) -> crate::error::Result<T>
where
    F: FnOnce(&mut UnveilBuilder) -> crate::error::Result<T>,
{
    let mut builder = UnveilBuilder { _private: () };
    let r = f(&mut builder)?;
    builder.finalize().map(|()| r)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::fs::File;
    use std::io::{Read, Write};
    use tempfile::TempDir;

    fn random_temp_directory() -> TempDir {
        TempDir::new().unwrap()
    }

    #[test]
    fn test_with_unveil() {
        let dir = random_temp_directory();
        let base_path = dir.path();

        println!("Testing on base: {}", base_path.display());
        let readonly = base_path.join("subdir").join("readonly");
        let writeonly = base_path.join("subdir").join("dropbox");
        let noperms = base_path.join("secret");

        println!("Creating directory: {}", readonly.display());
        fs::create_dir_all(&readonly).expect("Directory creation failed when it shouldn't have.");

        println!("Creating directory: {}", writeonly.display());
        fs::create_dir_all(&writeonly).expect("Directory creation failed when it shouldn't have.");

        println!("Creating directory: {}", noperms.display());
        fs::create_dir_all(&noperms).expect("Directory creation failed when it shouldn't have.");

        // Create files...

        File::create(readonly.join("myservice.conf"))
            .expect("File creation failed when it shouldn't have.");

        File::create(base_path.join("icanread.txt"))
            .expect("File creation failed when it shouldn't have.");

        let mut f = File::create(noperms.join("supersecret.txt"))
            .expect("File creation failed when it shouldn't have.");
        f.write_all("super secret message".as_bytes())
            .expect("File writing failed when it shouldn't have.");

        // base/
        // |- subdir/
        // |   |- readonly/
        // |   |    |- myservice.conf
        // |   |- dropbox/
        // |- secret/
        //      |- supersecret.txt

        // Lock down the process permissions using with_unveil.
        with_unveil(|u| {
            // Allow reading from the base directory by default.
            u.unveil(&base_path, UnveilPermissions::READ)?;

            // our dropbox is where we can write and create files.
            u.unveil(
                &writeonly,
                UnveilPermissions::WRITE | UnveilPermissions::CREATE,
            )?;

            // secret directory - nothing is allowed here.
            u.unveil(&noperms, UnveilPermissions::NONE)?;

            Ok(())
        })
        .expect("Unveiling failed.");

        // NOTE: File::create opens with the mode "wc"
        //       File::open opens with the mode "r"

        // Create a file on /etc (not allowed)
        // ::create = WRITE | CREATE
        let test = File::create("/etc/example");
        assert!(test.is_err());

        // Create a file under the base directory (not allowed)
        // ::create = WRITE | CREATE
        let test = File::create(base_path.join("example"));
        assert!(test.is_err());

        // Create a file under the dropbox (allowed)
        // ::create = WRITE | CREATE
        let f = File::create(writeonly.join("example.log"));
        assert!(f.is_ok());

        let mut f = f.unwrap();

        // Write to that file (allowed)
        let test = f.write_all("[INFO] thing happened!".as_bytes());
        assert!(test.is_ok());

        // Read from the dropbox (not allowed)
        let mut s = String::new();
        let test = f.read_to_string(&mut s);
        assert!(test.is_err());

        // Try to open the secret file (not allowed)
        let mut test = File::open(noperms.join("supersecret.txt"));
        assert!(test.is_err());
    }
}
