# obsd-guard

A misuse-resistant API for the [`pledge(2)`](https://man.openbsd.org/pledge) 
and [`unveil(2)`](https://man.openbsd.org/unveil) syscalls on OpenBSD.

## Example Use

```rust
fn main() -> obsd_guard::Result<()> {
    use obsd_guard::{with_unveil, UnveilPermissions, pledge, Promise};

    let operating_perms = Promise::STDIO | Promise::RPATH | Promise::UNIX;

    // Build the initial pledge from the steady-state pledge so the later,
    // tighter pledge is guaranteed to be a subset of the initial one.
    let initial_perms = operating_perms
        | Promise::BPF | Promise::WPATH | Promise::UNVEIL | Promise::CPATH;

    // Pledge with the setup-time permissions.
    pledge(initial_perms);

    with_unveil(|u| {
        u.unveil("/etc/myservice.conf", UnveilPermissions::READ)?;

        u.unveil("/var/run/service.sock",
                 UnveilPermissions::READ | UnveilPermissions::WRITE | UnveilPermissions::CREATE
        )?;

        Ok(())
    })?;
    // At this point, unveil has been permanently locked for the process.
    // Further attempts to change the unveil table will fail.

    // Finally, pledge with our steady-state permissions.
    pledge(operating_perms);
}
```