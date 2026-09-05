/* Copyright (C) 2026 Bumble Bee contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! OS-level hardening for the browser process.
//!
//! This layer complements the in-process execution sandbox. It is deliberately
//! conservative: it prevents privilege escalation and unexpected child-process
//! creation where the platform API permits it, while leaving normal Servo
//! rendering in the current process intact.
//!
//! A future multi-process renderer can use this same policy at the renderer
//! process boundary and then add filesystem/network namespaces or a platform
//! broker. This module must not be described as a complete kernel sandbox.

#[derive(Debug)]
pub(crate) enum SandboxError {
    Unsupported,
    OsError(&'static str, i32),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(f, "OS sandbox hardening is unsupported on this target"),
            Self::OsError(operation, code) => write!(f, "{operation} failed with OS error {code}"),
        }
    }
}

/// Apply the strongest safe process-level restrictions available without
/// replacing Servo's process architecture.
pub(crate) fn apply() -> Result<(), SandboxError> {
    platform::apply()
}

#[cfg(target_os = "linux")]
mod platform {
    use super::SandboxError;

    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
    const PR_SET_DUMPABLE: libc::c_int = 4;

    pub(super) fn apply() -> Result<(), SandboxError> {
        // Prevent execve() from gaining new privileges through setuid/setgid or
        // file capabilities. This is a kernel-enforced property inherited by
        // descendants.
        let no_new_privs = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if no_new_privs != 0 {
            return Err(SandboxError::OsError("prctl(PR_SET_NO_NEW_PRIVS)", errno()));
        }

        // Reduce the usefulness of ptrace/core-dump based attacks against the
        // browser process. Debug builds can opt out by not calling apply().
        let dumpable = unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if dumpable != 0 {
            return Err(SandboxError::OsError("prctl(PR_SET_DUMPABLE)", errno()));
        }

        Ok(())
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::SandboxError;
    use std::ffi::c_void;
    use std::ptr::null_mut;

    type HANDLE = *mut c_void;
    type DWORD = u32;
    type BOOL = i32;

    const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
    const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: DWORD = 0x0000_0008;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x0000_2000;
    const JobObjectExtendedLimitInformation: DWORD = 9;

    #[repr(C)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        per_process_user_time: i64,
        per_job_user_time: i64,
        limit_flags: DWORD,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: DWORD,
        affinity: usize,
        priority_class: DWORD,
        scheduling_class: DWORD,
    }

    #[repr(C)]
    struct IO_COUNTERS {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        io_info: IO_COUNTERS,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> HANDLE;
        fn SetInformationJobObject(
            job: HANDLE,
            info_class: DWORD,
            info: *mut c_void,
            info_length: DWORD,
        ) -> BOOL;
        fn AssignProcessToJobObject(job: HANDLE, process: HANDLE) -> BOOL;
        fn GetCurrentProcess() -> HANDLE;
        fn CloseHandle(object: HANDLE) -> BOOL;
        fn GetLastError() -> DWORD;
    }

    pub(super) fn apply() -> Result<(), SandboxError> {
        unsafe {
            let job = CreateJobObjectW(null_mut(), std::ptr::null());
            if job.is_null() || job == INVALID_HANDLE_VALUE {
                return Err(SandboxError::OsError("CreateJobObjectW", GetLastError() as i32));
            }

            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                    per_process_user_time: 0,
                    per_job_user_time: 0,
                    limit_flags: JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    minimum_working_set_size: 0,
                    maximum_working_set_size: 0,
                    active_process_limit: 1,
                    affinity: 0,
                    priority_class: 0,
                    scheduling_class: 0,
                },
                io_info: IO_COUNTERS {
                    read_operation_count: 0,
                    write_operation_count: 0,
                    other_operation_count: 0,
                    read_transfer_count: 0,
                    write_transfer_count: 0,
                    other_transfer_count: 0,
                },
                process_memory_limit: 0,
                job_memory_limit: 0,
                peak_process_memory_used: 0,
                peak_job_memory_used: 0,
            };

            if SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &mut limits as *mut _ as *mut c_void,
                std::mem::size_of_val(&limits) as DWORD,
            ) == 0 {
                let error = GetLastError() as i32;
                CloseHandle(job);
                return Err(SandboxError::OsError("SetInformationJobObject", error));
            }

            if AssignProcessToJobObject(job, GetCurrentProcess()) == 0 {
                let error = GetLastError() as i32;
                CloseHandle(job);
                return Err(SandboxError::OsError("AssignProcessToJobObject", error));
            }

            // Keep the job handle open for the lifetime of the process. Closing
            // it would activate JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
            std::mem::forget(job);
        }

        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod platform {
    use super::SandboxError;

    pub(super) fn apply() -> Result<(), SandboxError> {
        Err(SandboxError::Unsupported)
    }
}
