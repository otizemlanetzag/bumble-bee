/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use cfg_if::cfg_if;

#[cfg(test)]
mod test;

#[cfg(not(target_os = "android"))]
mod backtrace;
#[cfg(not(target_env = "ohos"))]
mod crash_handler;
#[cfg(not(any(target_os = "android", target_env = "ohos")))]
pub(crate) mod desktop;
#[cfg(any(target_os = "android", target_env = "ohos"))]
mod egl;
#[cfg(not(any(target_os = "android", target_env = "ohos")))]
mod panic_hook;
mod parser;
mod prefs;
pub(crate) mod language_engine;
pub(crate) mod code_security_scanner;
mod os_sandbox;
#[cfg(not(any(target_os = "android", target_env = "ohos")))]
mod resources;
mod running_app_state;
mod webdriver;
mod window;

pub mod platform {
    #[cfg(target_os = "macos")]
    pub use crate::platform::macos::deinit;

    #[cfg(target_os = "macos")]
    pub mod macos;

    #[cfg(not(target_os = "macos"))]
    pub fn deinit(_clean_shutdown: bool) {}
}

#[cfg(not(any(target_os = "android", target_env = "ohos")))]
pub fn main() {
    if let Err(error) = os_sandbox::apply() {
        log::warn!("Bumble Bee OS sandbox hardening was not fully applied: {error}");
    }
    desktop::cli::main()
}

pub fn init_crypto() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Error initializing crypto provider");
}

pub fn init_tracing(filter_directives: Option<&str>) {
    #[cfg(not(feature = "tracing"))]
    {
        if filter_directives.is_some() {
            log::debug!("The tracing feature was not selected - ignoring trace filter directives");
        }
    }
    #[cfg(feature = "tracing")]
    {
        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = tracing_subscriber::registry();

        #[cfg(feature = "tracing-perfetto")]
        let subscriber = {
            let file = std::fs::File::create("servo.pftrace").unwrap();
            let perfetto_layer = tracing_perfetto::PerfettoLayer::new(std::sync::Mutex::new(file))
                .with_filter_by_marker(|field_name| field_name == "servo_profiling")
                .with_debug_annotations(true);
            subscriber.with(perfetto_layer)
        };

        #[cfg(all(feature = "tracing-hitrace", target_env = "ohos"))]
        let subscriber = {
            subscriber.with(HitraceLayer::default())
        };

        let filter_builder = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::level_filters::LevelFilter::OFF.into());

        let filter = filter_builder
            .parse(filter_directives.unwrap_or("warn"))
            .expect("failed to parse filter directives");
        let subscriber = subscriber.with(tracing_subscriber::filter::Targets::from(filter));
        tracing::subscriber::set_global_default(subscriber)
            .expect("failed to set global tracing subscriber");
    }
}
