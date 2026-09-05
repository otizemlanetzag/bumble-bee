/* Copyright (C) 2026 Bumble Bee contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! OS hardening helpers for untrusted content processes.
//! Defense-in-depth only; this is not a complete kernel sandbox.

#![allow(unsafe_code)]

pub(crate) fn apply() -> Result<(), String> {
    platform::apply()
}

#[cfg(target_os = "linux")]
mod platform {
    pub(super) fn apply() -> Result<(), String> {
        set_limit(libc::RLIMIT_NOFILE, 4096)?;
        set_limit(libc::RLIMIT_CORE, 0)?;
        Ok(())
    }

    fn set_limit(resource: libc::__rlimit_resource_t, value: libc::rlim_t) -> Result<(), String> {
        let limit = libc::rlimit { rlim_cur: value, rlim_max: value };
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            return Err(format!("setrlimit failed: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use std::ffi::c_void;
    type DWORD = u32;
    type BOOL = i32;
    const EXTENSION_POINT_DISABLE: DWORD = 6;
    const STRICT_HANDLE_CHECK: DWORD = 3;
    const IMAGE_LOAD_POLICY: DWORD = 10;
    const IMAGE_LOAD_NO_REMOTE: DWORD = 0x1;
    const IMAGE_LOAD_NO_LOW_LABEL: DWORD = 0x2;
    const IMAGE_LOAD_PREFER_SYSTEM32: DWORD = 0x4;

    #[link(name = "kernel32")]
    extern "system" {
        fn SetProcessMitigationPolicy(policy: DWORD, buffer: *const c_void, size: usize) -> BOOL;
    }

    pub(super) fn apply() -> Result<(), String> {
        unsafe {
            let extension_points: DWORD = 1;
            set(EXTENSION_POINT_DISABLE, &extension_points)?;
            let strict_handles: DWORD = 1;
            set(STRICT_HANDLE_CHECK, &strict_handles)?;
            let image_load = IMAGE_LOAD_NO_REMOTE | IMAGE_LOAD_NO_LOW_LABEL | IMAGE_LOAD_PREFER_SYSTEM32;
            set(IMAGE_LOAD_POLICY, &image_load)?;
        }
        Ok(())
    }

    unsafe fn set<T>(policy: DWORD, value: &T) -> Result<(), String> {
        if SetProcessMitigationPolicy(policy, value as *const T as *const c_void, std::mem::size_of::<T>()) == 0 {
            return Err(format!("SetProcessMitigationPolicy({policy}) failed: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod platform {
    pub(super) fn apply() -> Result<(), String> { Ok(()) }
}
