/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#![deny(unsafe_code)]

extern crate embedder;
extern crate euclid;
extern crate log;
extern crate rustc_hash;
extern crate servo;

mod clipboard;
mod constellation;
mod crash_handler;
mod desktop;
mod headless;
mod init;
pub(crate) mod os_sandbox;
mod panic_hook;
mod prefs;
mod resources;
mod script_traits;
mod webdriver;

pub(crate) mod code_security_scanner;
pub(crate) mod language_engine;

pub use desktop::cli::main;

fn main() {
    desktop::cli::main();
}
