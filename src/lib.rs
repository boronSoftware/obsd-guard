//!
//! # obsd-guard
//!
//! A misuse-resistant API for the [`pledge(2)`] and [`unveil(2)`] syscalls on OpenBSD.
//!
//! **Note:** this crate will only compile on `target_os = "openbsd"`
//!
//! ## Choosing a `pledge` feature version
//!
//! The set of promises available for `pledge` has evolved across OpenBSD versions. For this reason,
//! ensure that you have selected a `pledge_X_Y` feature such that X and Y conform to the respective
//! major and minor versions of the oldest OpenBSD release that you intend to target.
//!
//! ## Example
//!
//! ```no_run
//! fn main() -> obsd_guard::Result<()> {
//!     use obsd_guard::{with_unveil, UnveilPermissions, pledge_with_exec, pledge, Promise};
//!
//!     let operating_perms = Promise::STDIO | Promise::RPATH | Promise::UNIX;
//!
//!     // Build the initial pledge from the steady-state pledge so the later,
//!     // tighter pledge is guaranteed to be a subset of the initial one.
//!     let initial_perms = operating_perms
//!         | Promise::BPF | Promise::WPATH | Promise::UNVEIL | Promise::CPATH;
//!
//!     // Pledge with the setup-time permissions.
//!     pledge(initial_perms);
//!
//!     with_unveil(|u| {
//!         u.unveil("/etc/myservice.conf", UnveilPermissions::READ)?;
//!
//!         u.unveil("/var/run/service.sock",
//!             UnveilPermissions::READ | UnveilPermissions::WRITE | UnveilPermissions::CREATE
//!         )?;
//!
//!         Ok(())
//!     })?;
//!     // At this point, unveil has been permanently locked for the process.
//!     // Further attempts to change the unveil table will fail.
//!
//!     // Finally, pledge with our steady-state permissions.
//!     pledge(operating_perms);
//! }
//! ```
//!
//! [`pledge(2)`]: https://man.openbsd.org/pledge
//! [`unveil(2)`]: https://man.openbsd.org/unveil

#[cfg(not(target_os = "openbsd"))]
compile_error!("obsd_guard only supports OpenBSD!");

pub mod error;
mod pledge;
mod unveil;
mod util;

pub use error::{Error, Result};
pub use pledge::{Promise, pledge, pledge_with_exec};
pub use unveil::{UnveilPermissions, with_unveil};
