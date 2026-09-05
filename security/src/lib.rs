// SPDX-License-Identifier: GPL-3.0-or-later
// Bumble Bee security layer. This independent component is GPLv3-or-later.

#![deny(unsafe_code)]

use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// The privacy policy interval: one hour between complete cookie-store cleanups.
pub const COOKIE_CLEANUP_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Adapter implemented by the browser/embedder to control its complete cookie store.
/// The implementation must delete the complete cookie store, not merely cookies for
/// the currently loaded URL.
pub trait CookieStoreController: Send + Sync + 'static {
    fn clear_all_cookies(&self);
}

/// Runs one cleanup operation. The browser integration and tests can invoke exactly
/// the same operation without duplicating policy logic.
pub fn cleanup_once(controller: &dyn CookieStoreController) {
    controller.clear_all_cookies();
}

/// Background service that performs a complete cookie-store cleanup every hour.
/// Dropping the service requests a clean shutdown and joins the worker.
pub struct CookieCleanupService {
    stop: Option<SyncSender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl CookieCleanupService {
    pub fn start(controller: Arc<dyn CookieStoreController>) -> std::io::Result<Self> {
        let (stop_tx, stop_rx) = sync_channel::<()>(0);

        let worker = thread::Builder::new()
            .name("bumble-bee-cookie-cleanup".to_owned())
            .spawn(move || loop {
                match stop_rx.recv_timeout(COOKIE_CLEANUP_INTERVAL) {
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => cleanup_once(controller.as_ref()),
                }
            })?;

        Ok(Self {
            stop: Some(stop_tx),
            worker: Some(worker),
        })
    }

    /// Stop the worker immediately. No extra cleanup is triggered during shutdown.
    pub fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for CookieCleanupService {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestController(AtomicUsize);

    impl CookieStoreController for TestController {
        fn clear_all_cookies(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn policy_is_exactly_one_hour() {
        assert_eq!(COOKIE_CLEANUP_INTERVAL, Duration::from_secs(3_600));
    }

    #[test]
    fn cleanup_once_calls_the_controller() {
        let controller = TestController(AtomicUsize::new(0));
        cleanup_once(&controller);
        assert_eq!(controller.0.load(Ordering::SeqCst), 1);
    }
}
