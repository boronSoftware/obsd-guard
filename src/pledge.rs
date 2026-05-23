#[cfg(all(
    feature = "_pledge",
    not(any(
        feature = "pledge_5_9",
        feature = "pledge_6_0",
        feature = "pledge_6_1",
        feature = "pledge_6_3",
        feature = "pledge_6_4",
        feature = "pledge_6_5",
        feature = "pledge_6_8",
    ))
))]
compile_error!(
    "Enable a specific `pledge_X_Y` feature that is less than or equal to the targeted OpenBSD version."
);

use std::fmt::Formatter;

#[cfg(target_os = "openbsd")]
mod openbsd_ext {
    use crate::Result;
    use std::ffi::CString;
    use std::io;

    pub(super) fn pledge(promises: Option<&str>, execpromises: Option<&str>) -> Result<()> {
        let promises_c = match promises {
            Some(v) => Some(CString::new(v).expect(
                "invariant violated: pledge `promises` argument cannot be converted into a CString",
            )),
            None => None,
        };
        let execpromises_c = match execpromises {
            Some(v) => Some(CString::new(v).expect("invariant violated: pledge `execpromises` argument cannot be converted into a CString")),
            None => None,
        };

        let promises_ptr = promises_c.as_ref().map_or(std::ptr::null(), |f| f.as_ptr());
        let execpromises_ptr = execpromises_c
            .as_ref()
            .map_or(std::ptr::null(), |f| f.as_ptr());

        let result = unsafe { libc::pledge(promises_ptr, execpromises_ptr) };

        if result == 0 {
            Ok(())
        } else {
            Err(crate::Error::Pledge(io::Error::last_os_error()))
        }
    }
}

///
/// A set of OpenBSD [`pledge(2)`](https://man.openbsd.org/OpenBSD-7.8/pledge) promises.
///
/// Docstrings are (mostly) copied from the manpage.
/// Others are copied from `sys/pledge.h`.
///
#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct Promise(u64);

impl Promise {
    pub const NONE: Self = Self(0);

    /// A number of system calls are allowed which allow path
    /// traversal, reading _struct stat_, and opening files for
    /// read.
    pub const RPATH: Self = Self(0x0000_0000_0000_0001);
    /// Similar to [`Promise::RPATH`], but files can be opened for write.
    pub const WPATH: Self = Self(0x0000_0000_0000_0002);
    /// Similar to [`Promise::WPATH`], but files can also be created.
    pub const CPATH: Self = Self(0x0000_0000_0000_0004);
    /// The following system calls are permitted.  `sendto(2)` is
    /// only permitted if its destination socket address is
    /// `NULL`.  As a result, all the expected functionalities of
    /// libc stdio work.
    ///
    /// `clock_getres(2)`, `clock_gettime(2)`, `close(2)`,
    /// `closefrom(2)`, `dup(2)`, `dup2(2)`, `dup3(2)`, `fchdir(2)`,
    /// `fcntl(2)`, `fstat(2)`, `fsync(2)`, `ftruncate(2)`,
    /// `getdtablecount(2)`, `getegid(2)`, `getentropy(2)`,
    /// `geteuid(2)`, `getgid(2)`, `getgroups(2)`, `getitimer(2)`,
    /// `getlogin(2)`, `getpgid(2)`, `getpgrp(2)`, `getpid(2)`,
    /// `getppid(2)`, `getresgid(2)`, `getresuid(2)`, `getrlimit(2)`,
    /// `getrtable(2)`, `getsid(2)`, `getthrid(2)`, `gettimeofday(2)`,
    /// `getuid(2)`, `issetugid(2)`, `kevent(2)`, `kqueue(2)`,
    /// `kqueue1(2)`, `lseek(2)`, `madvise(2)`, `minherit(2)`, `mmap(2)`,
    /// `mprotect(2)`, `mquery(2)`, `munmap(2)`, `nanosleep(2)`,
    /// `pipe(2)`, `pipe2(2)`, `poll(2)`, `pread(2)`, `preadv(2)`,
    /// `profil(2)`, `pwrite(2)`, `pwritev(2)`, `read(2)`, `readv(2)`,
    /// `recvfrom(2)`, `recvmsg(2)`, `select(2)`, `sendmsg(2)`,
    /// `sendsyslog(2)`, `sendto(2)`, `setitimer(2)`, `shutdown(2)`,
    /// `sigaction(2)`, `sigprocmask(2)`, `sigreturn(2)`,
    /// `socketpair(2)`, `umask(2)`, `wait4(2)`, `waitid(2)`, `write(2)`,
    /// `writev(2)`
    pub const STDIO: Self = Self(0x0000_0000_0000_0008);
    /// Some low-level behaviours required by the DNS resolver res_init(3) are
    /// permitted, such as opening `resolv.conf(5)` and a few networking system
    /// calls: `socket(2)`, `connect(2)`, `sendto(2)`, `recvfrom(2)`.
    ///
    /// To distinguish the dns promise from inet, the libc DNS code opens
    /// sockets with the `SOCK_DNS` flag which OpenBSD requires to
    /// communicate with `AF_INET` and `AF_INET6` at port 53.
    pub const DNS: Self = Self(0x0000_0000_0000_0020);
    /// The following system calls are allowed to operate in the `AF_INET`
    /// and `AF_INET6` domains (though `setsockopt(2)` has been substantially
    /// reduced in functionality):
    ///
    /// `socket(2)`, `listen(2)`, `bind(2)`, `connect(2)`, `accept4(2)`,
    /// `accept(2)`, `getpeername(2)`, `getsockname(2)`, `setsockopt(2)`,
    /// `getsockopt(2)`
    pub const INET: Self = Self(0x0000_0000_0000_0040);
    /// File locking via `fcntl(2)`, `flock(2)`, `lockf(3)`, and `open(2)` is
    /// allowed.
    ///
    /// No distinction is made between shared and exclusive locks. This promise
    /// is required for unlock as well as lock.
    pub const FLOCK: Self = Self(0x0000_0000_0000_0080);
    /// The following system calls are allowed to operate in the `AF_UNIX`
    /// domain:
    ///
    /// `socket(2)`, `listen(2)`, `bind(2)`, `connect(2)`, `accept4(2)`,
    /// `accept(2)`, `getpeername(2)`, `getsockname(2)`, `setsockopt(2)`,
    /// `getsockopt(2)`
    pub const UNIX: Self = Self(0x0000_0000_0000_0100);
    /// Allows the following system calls which can change the rights of a
    /// process:
    ///
    /// `setuid(2)`, `seteuid(2)`, `setreuid(2)`, `setresuid(2)`, `setgid(2)`,
    /// `setegid(2)`, `setregid(2)`, `setresgid(2)`, `setgroups(2)`,
    /// `setlogin(2)`, `setrlimit(2)`, `getpriority(2)`, `setpriority(2)`,
    /// `setrtable(2)`
    pub const ID: Self = Self(0x0000_0000_0000_0200);
    /// Allow `MTIOCGET` and `MTIOCTOP` operations against tape drives.
    ///
    /// # Availability
    /// OpenBSD >= 6.1
    #[cfg(feature = "pledge_6_1")]
    pub const TAPE: Self = Self(0x0000_0000_0000_0400);
    /// This allows read-only opening of files in `/etc` for the `getpwnam(3)`,
    /// `getgrnam(3)`, `getgrouplist(3)`, and `initgroups(3)` family of
    /// functions, including lookups via the `yp(8)` protocol for YP and
    /// LDAP databases.
    pub const GETPW: Self = Self(0x0000_0000_0000_0800);
    /// Allows the following process relationship operations:
    ///
    /// `fork(2)`, `vfork(2)`, `kill(2)`, `getpriority(2)`, `setpriority(2)`,
    /// `setrlimit(2)`, `setpgid(2)`, `setsid(2)`
    pub const PROC: Self = Self(0x0000_0000_0000_1000);
    /// Allows the setting of system time, via the `settimeofday(2)`,
    /// `adjtime(2)`, and `adjfreq(2)` system calls.
    pub const SETTIME: Self = Self(0x0000_0000_0000_2000);
    /// The following system calls are allowed to make explicit changes to
    /// fields in struct stat relating to a file:
    ///
    /// `utimes(2)`, `futimes(2)`, `utimensat(2)`, `futimens(2)`, `chmod(2)`,
    /// `fchmod(2)`, `fchmodat(2)`, `chflags(2)`, `chflagsat(2)`,
    /// `chown(2)`, `fchownat(2)`, `lchown(2)`, `fchown(2)`, `utimes(2)`
    pub const FATTR: Self = Self(0x0000_0000_0000_4000);
    /// Allows the use of `PROT_EXEC` with `mmap(2)` and `mprotect(2)`.
    pub const PROT_EXEC: Self = Self(0x0000_0000_0000_8000);
    /// In addition to allowing read-write operations on `/dev/tty`, this opens
    /// up a variety of `ioctl(2)` requests used by `tty` devices. If `tty`
    /// is accompanied with `rpath`, `revoke(2)` is permitted. Otherwise
    /// only the following `ioctl(2)` requests are permitted:
    ///
    /// `TIOCSPGRP`, `TIOCGETA`, `TIOCGPGRP`, `TIOCGWINSZ`, `TIOCSWINSZ`,
    /// `TIOCSBRK`, `TIOCCDTR`, `TIOCSETA`, `TIOCSETAW`, `TIOCSETAF`,
    /// `TIOCUCNTL`
    pub const TTY: Self = Self(0x0000_0000_0001_0000);
    /// Allows sending of file descriptors using `sendmsg(2)`. File descriptors
    /// referring to directories may not be passed.
    pub const SENDFD: Self = Self(0x0000_0000_0002_0000);
    /// Allows receiving of file descriptors using `recvmsg(2)`. File
    /// descriptors referring to directories may not be passed.
    pub const RECVFD: Self = Self(0x0000_0000_0004_0000);
    /// Allows a process to call `execve(2)`. Coupled with the proc promise,
    /// this allows a process to fork and execute another program. If
    /// _execpromises_ has been previously set, the new program begins with
    /// those promises, unless `setuid`/`setgid` bits are set in which case
    /// execution is blocked with `EACCES`. Otherwise, the new program
    /// starts running without pledge active, and hopefully makes a new
    /// pledge soon.
    pub const EXEC: Self = Self(0x0000_0000_0008_0000);
    /// Allow inspection of the routing table.
    ///
    /// # Availability
    /// OpenBSD >= 6.1
    #[cfg(feature = "pledge_6_1")]
    pub const ROUTE: Self = Self(0x0000_0000_0010_0000);
    /// In combination with inet give back functionality to `setsockopt(2)` for
    /// operating on multicast sockets.
    ///
    /// # Availability
    /// OpenBSD >= 6.1
    #[cfg(feature = "pledge_6_1")]
    pub const MCAST: Self = Self(0x0000_0000_0020_0000);
    /// Allows enough `sysctl(2)` interfaces to allow inspection of the system's
    /// virtual memory by programs like `top(1)` and `vmstat(8)`.
    pub const VMINFO: Self = Self(0x0000_0000_0040_0000);
    /// Allows enough `sysctl(2)` interfaces to allow inspection of processes
    /// operating on the system using programs like `ps(1)`.
    pub const PS: Self = Self(0x0000_0000_0080_0000);
    /// disklabels
    ///
    /// # Availability
    /// OpenBSD >=6.1
    #[cfg(feature = "pledge_6_1")]
    pub const DISKLABEL: Self = Self(0x0000_0000_0200_0000);
    /// Allows a subset of `ioctl(2)` operations on the `pf(4)` device:
    ///
    /// `DIOCADDRULE`, `DIOCGETSTATUS`, `DIOCNATLOOK`, `DIOCRADDTABLES`,
    /// `DIOCRCLRADDRS`, `DIOCRCLRTABLES`, `DIOCRCLRTSTATS`,
    /// `DIOCRGETTSTATS`, `DIOCRSETADDRS`, `DIOCXBEGIN`, `DIOCXCOMMIT`
    pub const PF: Self = Self(0x0000_0000_0400_0000);
    /// Allows a subset of `ioctl(2)` operations on audio(4) devices (see
    /// `sio_open(3)` for more information):
    ///
    /// `AUDIO_GETPOS`, `AUDIO_GETPAR`, `AUDIO_SETPAR`, `AUDIO_START`,
    /// `AUDIO_STOP`, `AUDIO_MIXER_DEVINFO`, `AUDIO_MIXER_READ`,
    /// `AUDIO_MIXER_WRITE`
    pub const AUDIO: Self = Self(0x0000_0000_0800_0000);
    /// Similar to [`Promise::CPATH`], but special files can be created using:
    /// `mkfifo(2)`, `mknod(2)`
    pub const DPATH: Self = Self(0x0000_0000_1000_0000);
    /// drm ioctls
    ///
    /// # Availability
    /// OpenBSD >=6.1
    #[cfg(feature = "pledge_6_1")]
    pub const DRM: Self = Self(0x0000_0000_2000_0000);
    /// vmm ioctls
    ///
    /// # Availability
    /// OpenBSD >=6.1
    #[cfg(feature = "pledge_6_1")]
    pub const VMM: Self = Self(0x0000_0000_4000_0000);
    /// The `chown(2)` family is allowed to change the user or group on a file.
    ///
    /// # Availability
    /// OpenBSD >=6.0
    #[cfg(feature = "pledge_6_0")]
    pub const CHOWN: Self = Self(0x0000_0000_8000_0000);
    /// Allow `BIOCGSTATS` operation for statistics collection from a `bpf(4)`
    /// device.
    ///
    /// # Availability
    /// OpenBSD >= 6.1
    #[cfg(feature = "pledge_6_1")]
    pub const BPF: Self = Self(0x0000_0002_0000_0000);
    /// Rather than killing the process upon violation, indicate error with
    /// `ENOSYS`.
    ///
    /// Also, when `pledge()` is called with higher _promises_ or
    /// _execpromises_, those changes will be ignored and return success. This
    /// is useful when a parent enforces _execpromises_ but an `execve`'d
    /// child has a different idea.
    ///
    /// # Availability
    /// OpenBSD >= 6.3
    #[cfg(feature = "pledge_6_3")]
    pub const ERROR: Self = Self(0x0000_0004_0000_0000);
    /// Allow changes to the routing table.
    ///
    /// # Availability
    /// OpenBSD >= 6.8
    #[cfg(feature = "pledge_6_8")]
    pub const WROUTE: Self = Self(0x0000_0008_0000_0000);
    /// Allow unveil(2) to be called.
    ///
    /// # Availability
    /// OpenBSD >= 6.4
    #[cfg(feature = "pledge_6_4")]
    pub const UNVEIL: Self = Self(0x0000_0010_0000_0000);
    /// Allows a subset of `ioctl(2)` operations on `video(4)` devices:
    ///
    /// `VIDIOC_DQBUF`, `VIDIOC_ENUM_FMT`, `VIDIOC_ENUM_FRAMEINTERVALS`,
    /// `VIDIOC_ENUM_FRAMESIZES`, `VIDIOC_G_CTRL`, `VIDIOC_G_PARM`,
    /// `VIDIOC_QBUF`, `VIDIOC_QUERYBUF`, `VIDIOC_QUERYCAP`,
    /// `VIDIOC_QUERYCTRL`, `VIDIOC_S_CTRL`, `VIDIOC_S_FMT`,
    /// `VIDIOC_S_PARM`, `VIDIOC_STREAMOFF`, `VIDIOC_STREAMON`,
    /// `VIDIOC_TRY_FMT`, `VIDIOC_REQBUFS`
    ///
    /// # Availability
    /// OpenBSD >= 6.5
    #[cfg(feature = "pledge_6_5")]
    pub const VIDEO: Self = Self(0x0000_0020_0000_0000);
    /// Allows a subset of ioctl(2) operations:
    ///
    /// `FIOCLEX`, `FIONCLEX`, `FIOASYNC`, `FIOGETOWN`, and `FIOSETOWN`. On a
    /// tty device `TIOCGETA` will succeed otherwise fail with `EPERM`. On a tty
    /// device, `TIOCGPGRP` and `TIOCGWINSZ` are allowed. A few other
    /// operations are allowed, but not listed here.
    ///
    /// # Availability
    /// OpenBSD 5.9 through 6.0; removed in OpenBSD 6.1.
    #[cfg(all(feature = "pledge_5_9", not(feature = "pledge_6_1")))]
    pub const IOCTL: Self = Self(0x0000_0040_0000_0000);

    /// Translate the promise into a space-separated string.
    pub fn to_keyword_string(&self) -> String {
        const TABLE: &[(&u64, &str)] = &[
            (&Promise::RPATH.0, "rpath"),
            (&Promise::WPATH.0, "wpath"),
            (&Promise::CPATH.0, "cpath"),
            (&Promise::STDIO.0, "stdio"),
            (&Promise::DNS.0, "dns"),
            (&Promise::INET.0, "inet"),
            (&Promise::FLOCK.0, "flock"),
            (&Promise::UNIX.0, "unix"),
            (&Promise::ID.0, "id"),
            #[cfg(feature = "pledge_6_1")]
            (&Promise::TAPE.0, "tape"),
            (&Promise::GETPW.0, "getpw"),
            (&Promise::PROC.0, "proc"),
            (&Promise::SETTIME.0, "settime"),
            (&Promise::FATTR.0, "fattr"),
            (&Promise::PROT_EXEC.0, "prot_exec"),
            (&Promise::TTY.0, "tty"),
            (&Promise::SENDFD.0, "sendfd"),
            (&Promise::RECVFD.0, "recvfd"),
            (&Promise::EXEC.0, "exec"),
            #[cfg(feature = "pledge_6_1")]
            (&Promise::ROUTE.0, "route"),
            #[cfg(feature = "pledge_6_1")]
            (&Promise::MCAST.0, "mcast"),
            (&Promise::VMINFO.0, "vminfo"),
            (&Promise::PS.0, "ps"),
            #[cfg(feature = "pledge_6_1")]
            (&Promise::DISKLABEL.0, "disklabel"),
            (&Promise::PF.0, "pf"),
            (&Promise::AUDIO.0, "audio"),
            (&Promise::DPATH.0, "dpath"),
            #[cfg(feature = "pledge_6_1")]
            (&Promise::DRM.0, "drm"),
            #[cfg(feature = "pledge_6_1")]
            (&Promise::VMM.0, "vmm"),
            #[cfg(feature = "pledge_6_0")]
            (&Promise::CHOWN.0, "chown"),
            #[cfg(feature = "pledge_6_1")]
            (&Promise::BPF.0, "bpf"),
            #[cfg(feature = "pledge_6_3")]
            (&Promise::ERROR.0, "error"),
            #[cfg(feature = "pledge_6_8")]
            (&Promise::WROUTE.0, "wroute"),
            #[cfg(feature = "pledge_6_4")]
            (&Promise::UNVEIL.0, "unveil"),
            #[cfg(feature = "pledge_6_5")]
            (&Promise::VIDEO.0, "video"),
            #[cfg(all(feature = "pledge_5_9", not(feature = "pledge_6_1")))]
            (&Promise::IOCTL.0, "ioctl"),
        ];

        let mut out = String::new();
        for (n, s) in TABLE {
            if self.0 & *n != 0 {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(s);
            }
        }

        out
    }

    pub fn is_subset_of(self, other: Self) -> bool {
        // is every bit in `self` also in `other`?
        // self ∩ ¬other == ∅
        (self.0 & !other.0) == 0
    }

    pub fn contains(self, other: Self) -> bool {
        // other ∩ ¬self == ∅
        other.is_subset_of(self)
    }
}

impl std::ops::BitOr for Promise {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for Promise {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

impl std::fmt::Debug for Promise {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Promise {{ {} }}", self.to_keyword_string())
    }
}

///
/// [`pledge`] restricts the permissions of the current process without changing the permissions
/// of child processes called through [`execve(2)`](https://man.openbsd.org/execve.2)
///
/// Under the hood, this invokes the `pledge` syscall with `NULL` for the `execpromises` argument.
///
/// # Example
///
/// ```rust
/// use obsd_guard::{pledge, Promise};
///
/// let needed_init = Promise::STDIO
///     | Promise::DRM | Promise::VMINFO
///     | Promise::DISKLABEL | Promise::BPF;
///
/// pledge(needed_init);
///
/// ```
///
pub fn pledge(promises: Promise) -> crate::Result<()> {
    let promises_str = promises.to_keyword_string();
    openbsd_ext::pledge(Some(&promises_str), None)
}

/// Restricts the operations that the current process can perform and further
/// restricts the operations executable subprocesses are allowed to perform
/// using OpenBSD's `pledge` system call.
///
/// This function allows specifying separate sets of promises for the current
/// process **and for any executables that it may invoke.**
pub fn pledge_with_exec(promises: Promise, exec_promises: Promise) -> crate::Result<()> {
    let promises_str = promises.to_keyword_string();
    let exec_promises_str = exec_promises.to_keyword_string();

    openbsd_ext::pledge(Some(&promises_str), Some(&exec_promises_str))
}
