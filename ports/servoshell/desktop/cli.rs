/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::{env, panic};

use crate::desktop::app::App;
use crate::desktop::event_loop::ServoShellEventLoop;
use crate::panic_hook;
use crate::prefs::{ArgumentParsingResult, parse_command_line_arguments};

pub fn main() {
    crate::crash_handler::install();
    crate::init_crypto();

    // TODO: once log-panics is released, can this be replaced by
    // log_panics::init()?
    panic::set_hook(Box::new(panic_hook::panic_hook));

    // Skip the first argument, which is the binary name.
    let args: Vec<String> = env::args().skip(1).collect();
    let (opts, preferences, servoshell_preferences) = match parse_command_line_arguments(&*args) {
        ArgumentParsingResult::ContentProcess(token) => {
            // Web content is untrusted. Apply independent hardening layers
            // before entering Servo's content-process runtime.
            if let Err(error) = crate::os_sandbox::apply() {
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                {
                    eprintln!("Bumble Bee content-process OS sandbox could not be applied: {error}");
                    std::process::exit(126);
                }
                #[cfg(not(any(target_os = "linux", target_os = "windows")))]
                {
                    eprintln!("Bumble Bee content-process OS sandbox is unavailable: {error}");
                }
            }

            if let Err(error) = crate::process_hardening::apply() {
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                {
                    eprintln!("Bumble Bee content-process hardening could not be applied: {error}");
                    std::process::exit(126);
                }
                #[cfg(not(any(target_os = "linux", target_os = "windows")))]
                {
                    eprintln!("Bumble Bee content-process hardening is unavailable: {error}");
                }
            }

            return servo::run_content_process(token);
        },
        ArgumentParsingResult::ChromeProcess(opts, preferences, servoshell_preferences) => {
            (opts, preferences, servoshell_preferences)
        },
        ArgumentParsingResult::Exit => {
            std::process::exit(0);
        },
        ArgumentParsingResult::ErrorParsing => {
            std::process::exit(1);
        },
    };

    crate::init_tracing(servoshell_preferences.tracing_filter.as_deref());

    let clean_shutdown = servoshell_preferences.clean_shutdown;
    let event_loop = match servoshell_preferences.headless {
        true => ServoShellEventLoop::headless(),
        false => ServoShellEventLoop::headed(),
    };

    {
        let mut app = App::new(opts, preferences, servoshell_preferences, &event_loop);
        event_loop.run_app(&mut app);
    }

    crate::platform::deinit(clean_shutdown)
}
