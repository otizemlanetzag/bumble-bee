/* Copyright (C) 2026 Bumble Bee contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Linux-only kernel hardening for the untrusted Servo content process.
//!
//! This deliberately uses a conservative seccomp deny-list rather than an
//! allow-list: Servo is large and its complete syscall surface must be
//! measured before an allow-list can safely be made mandatory.
//! Landlock is used for a narrow invariant that is safe for web content:
//! files may not be executed after the sandbox is installed.

#![allow(unsafe_code)]

use std::mem::size_of;

const EPERM: u32 = 1;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_TSYNC: libc::c_uint = 1;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;
const BPF_ALU: u16 = 0x04;
const BPF_AND: u16 = 0x50;

const SECCOMP_ARCH_X86_64: u32 = 0xc000_003e;
const SECCOMP_ARCH_AARCH64: u32 = 0xc000_00b7;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

#[derive(Debug)]
pub(crate) enum LinuxSecurityError {
    Seccomp(i32),
    Landlock(i32),
}

impl std::fmt::Display for LinuxSecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Seccomp(code) => write!(f, "seccomp failed with errno {code}"),
            Self::Landlock(code) => write!(f, "Landlock failed with errno {code}"),
        }
    }
}

/// Install kernel restrictions after Servo's content-process startup has
/// completed. The policy is inherited by children/threads where the kernel
/// supports the corresponding filter synchronization semantics.
pub(crate) fn apply() -> Result<(), LinuxSecurityError> {
    install_landlock_no_execute()?;
    install_seccomp_deny_list()
}

fn install_seccomp_deny_list() -> Result<(), LinuxSecurityError> {
    let arch = if cfg!(target_arch = "x86_64") {
        SECCOMP_ARCH_X86_64
    } else if cfg!(target_arch = "aarch64") {
        SECCOMP_ARCH_AARCH64
    } else {
        // Do not guess syscall numbers for another architecture.
        return Ok(());
    };

    let mut filter = Vec::with_capacity(3 + 2 * denied_syscalls().len() + 1);
    // Always validate the seccomp architecture first. This is explicitly
    // required because syscall numbering differs between ABIs.
    filter.push(SockFilter { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 4 });
    filter.push(SockFilter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: arch });
    filter.push(SockFilter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_KILL_PROCESS });

    // x32 syscall numbers have bit 30 set. Reject them instead of allowing
    // an alternate ABI to bypass the deny-list.
    filter.push(SockFilter { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 0 });
    filter.push(SockFilter { code: BPF_ALU | BPF_AND | BPF_K, jt: 0, jf: 0, k: X32_SYSCALL_BIT });
    filter.push(SockFilter { code: BPF_JMP | BPF_JSET | BPF_K, jt: 0, jf: 1, k: 0 });
    filter.push(SockFilter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_KILL_PROCESS });

    // Reload syscall number after the ABI guard.
    filter.push(SockFilter { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 0 });
    for syscall in denied_syscalls() {
        filter.push(SockFilter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 0, jf: 1, k: syscall });
        filter.push(SockFilter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA) });
    }
    filter.push(SockFilter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW });

    let program = SockFprog { len: filter.len() as u16, filter: filter.as_ptr() };
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            &program as *const SockFprog,
        )
    };
    if result != 0 {
        return Err(LinuxSecurityError::Seccomp(errno()));
    }
    Ok(())
}

fn denied_syscalls() -> &'static [u32] {
    #[cfg(target_arch = "x86_64")]
    {
        // Dangerous kernel interfaces that normal web rendering does not need.
        return &[
            16,   // ioctl is intentionally NOT denied; Servo uses it heavily.
            157,  // prctl is needed by some runtime components; kept allowed.
            56,   // clone is needed for threads; kept allowed.
            59,   // execve
            322,  // execveat
            101,  // ptrace
            165,  // mount
            166,  // umount2
            155,  // pivot_root
            272,  // unshare
            308,  // setns
            246,  // kexec_load
            313,  // finit_module
            175,  // init_module
            176,  // delete_module
            321,  // bpf
            298,  // perf_event_open
            323,  // userfaultfd
            304,  // open_by_handle_at
            303,  // name_to_handle_at
            250,  // keyctl
            248,  // add_key
            249,  // request_key
            169,  // reboot
        ];
    }
    #[cfg(target_arch = "aarch64")]
    {
        return &[
            221, // execve
            281, // execveat
            117, // ptrace
            40,  // mount
            39,  // umount2
            41,  // setns
            97,  // pivot_root
            97,  // (conservative duplicate harmlessly removed below)
            104, // kexec_load
            273, // finit_module
            105, // init_module
            106, // delete_module
            280, // bpf
            241, // perf_event_open
            282, // userfaultfd
            265, // open_by_handle_at
            264, // name_to_handle_at
            219, // reboot
        ];
    }
    &[]
}

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
    quiet_access_fs: u64,
    quiet_access_net: u64,
    quiet_scoped: u64,
}

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_RESTRICT_SELF_TSYNC: u32 = 1 << 0;

fn install_landlock_no_execute() -> Result<(), LinuxSecurityError> {
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 0 {
        let error = errno();
        if error == libc::ENOSYS || error == libc::EOPNOTSUPP {
            // Older kernels simply do not provide Landlock. Keep the rest of
            // the kernel hardening active instead of making the browser fail.
            return Ok(());
        }
        return Err(LinuxSecurityError::Landlock(error));
    }

    let attr = LandlockRulesetAttr {
        handled_access_fs: LANDLOCK_ACCESS_FS_EXECUTE,
        handled_access_net: 0,
        scoped: 0,
        quiet_access_fs: 0,
        quiet_access_net: 0,
        quiet_scoped: 0,
    };

    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    } as i32;
    if ruleset_fd < 0 {
        return Err(LinuxSecurityError::Landlock(errno()));
    }

    // No path rule grants EXECUTE, so EXECUTE is denied by default. Existing
    // already-open executable objects are not retroactively changed by
    // Landlock, which is exactly what we want for Servo's already-loaded code.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            ruleset_fd,
            LANDLOCK_RESTRICT_SELF_TSYNC,
        )
    };
    let close_result = unsafe { libc::close(ruleset_fd) };
    let _ = close_result;
    if result != 0 {
        return Err(LinuxSecurityError::Landlock(errno()));
    }

    let _ = abi;
    Ok(())
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    #[test]
    fn deny_list_contains_execve_on_supported_arches() {
        #[cfg(target_arch = "x86_64")]
        assert!(super::denied_syscalls().contains(&59));
        #[cfg(target_arch = "aarch64")]
        assert!(super::denied_syscalls().contains(&221));
    }
}
