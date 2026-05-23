use std::error::Error as StdError;
use std::fmt::Formatter;
use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    /// A path supplied to `unveil` contained an interior NUL byte, and thus could not be passed to
    /// the kernel as a C-string.
    PathContainsNul,
    /// The `pledge` syscall failed.
    ///
    /// - `EFAULT`: _promises_ or _execpromises_ points outside the process's allocated address
    /// space[^unreachable].
    /// - `EINVAL`: _promises_ is malformed or contains invalid keywords[^unreachable].
    /// - `EPERM`: This process is attempting to increase permissions.
    ///
    /// [^unreachable]: This error is not practically achievable when using this library.
    Pledge(io::Error),
    /// The `unveil` syscall failed.
    ///
    /// - `E2BIG`: The addition of path would exceed the per-process limit for unveiled paths.
    /// - `EFAULT`: _path_ or _permissions_ points outside the process's allocated address space[^unreachable].
    /// - `ENOENT`: A directory in path did not exist.
    /// - `EINVAL`: An invalid value of _permissions_ was used[^unreachable].
    /// - `EPERM`: An attempt to increase permissions was made, or the _path_ was not accessible,
    /// or `unveil()` was called after locking.
    ///
    /// [^unreachable]: This error is not practically achievable when using this library.
    Unveil(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::PathContainsNul => write!(f, "path value contains interior NUL byte"),
            Error::Pledge(err) => write!(f, "pledge failed: {err}"),
            Error::Unveil(err) => write!(f, "unveil failed: {err}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Pledge(err) | Error::Unveil(err) => Some(err),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
