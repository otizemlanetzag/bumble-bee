/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Browser download manager.
//!
//! This module is deliberately independent from the UI. Servo/servoshell can
//! feed it download requests and observe state changes without coupling the
//! network/file implementation to egui.
//!
//! Features:
//! - concurrent downloads
//! - pause/resume
//! - cancellation
//! - progress and speed reporting
//! - Content-Length and Content-Disposition filename handling
//! - safe filename/path handling
//! - collision-free destination names
//! - atomic ".part" files
//! - resumable metadata on disk
//! - HTTPS using Servo's existing rustls/hyper stack
//! - redirect handling with a bounded redirect count
//! - SHA-256 checksum of completed files

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use http::{header, HeaderValue, Request};
use hyper::body::Incoming;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use hyper_rustls::HttpsConnectorBuilder;
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::runtime::Builder;
use url::Url;
use uuid::Uuid;

const MAX_REDIRECTS: usize = 10;
const BUFFER_SIZE: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum DownloadStatus {
    Queued,
    Downloading,
    Paused,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DownloadInfo {
    pub id: Uuid,
    pub url: String,
    pub filename: String,
    pub destination: PathBuf,
    pub total_bytes: Option<u64>,
    pub downloaded_bytes: u64,
    pub status: DownloadStatus,
    pub error: Option<String>,
    pub sha256: Option<String>,
    pub speed_bytes_per_second: Option<u64>,
}

#[derive(Clone, Debug)]
pub enum DownloadEvent {
    Added(DownloadInfo),
    Progress(DownloadInfo),
    Completed(DownloadInfo),
    Cancelled(DownloadInfo),
    Failed(DownloadInfo),
}

#[derive(Default)]
struct Controls {
    paused: AtomicBool,
    cancelled: AtomicBool,
}

struct ActiveDownload {
    info: Mutex<DownloadInfo>,
    controls: Controls,
}

#[derive(Clone)]
pub struct DownloadManager {
    root: PathBuf,
    state_file: PathBuf,
    active: Arc<Mutex<HashMap<Uuid, Arc<ActiveDownload>>>>,
    listeners: Arc<Mutex<Vec<Arc<dyn Fn(DownloadEvent) + Send + Sync>>>>,
}

impl DownloadManager {
    /// Create a manager using the platform's Downloads directory.
    pub fn new() -> io::Result<Self> {
        let root = dirs::download_dir()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Downloads directory not found"))?;
        Self::with_root(root)
    }

    /// Create a manager using an explicit download directory.
    pub fn with_root(root: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&root)?;
        let state_file = root.join(".bumble-bee-downloads.json");
        let manager = Self {
            root,
            state_file,
            active: Arc::new(Mutex::new(HashMap::new())),
            listeners: Arc::new(Mutex::new(Vec::new())),
        };

        manager.load_state()?;
        Ok(manager)
    }

    /// Register a listener for download state/progress changes.
    pub fn subscribe<F>(&self, listener: F)
    where
        F: Fn(DownloadEvent) + Send + Sync + 'static,
    {
        self.listeners.lock().unwrap().push(Arc::new(listener));
    }

    /// Start a download and return its stable identifier.
    pub fn start(&self, url: Url, suggested_filename: Option<String>) -> io::Result<Uuid> {
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Only HTTP and HTTPS downloads are supported",
            ));
        }

        let id = Uuid::new_v4();
        let filename = suggested_filename
            .filter(|s| !s.trim().is_empty())
            .map(|s| sanitize_filename(&s))
            .unwrap_or_else(|| filename_from_url(&url));

        let filename = unique_filename(&self.root, &filename);
        let destination = self.root.join(&filename);

        let info = DownloadInfo {
            id,
            url: url.to_string(),
            filename,
            destination,
            total_bytes: None,
            downloaded_bytes: 0,
            status: DownloadStatus::Queued,
            error: None,
            sha256: None,
            speed_bytes_per_second: None,
        };

        let active = Arc::new(ActiveDownload {
            info: Mutex::new(info.clone()),
            controls: Controls::default(),
        });

        self.active.lock().unwrap().insert(id, active.clone());
        self.persist()?;
        self.emit(DownloadEvent::Added(info));

        let manager = self.clone();
        thread::Builder::new()
            .name(format!("bumble-bee-download-{id}"))
            .spawn(move || {
                if let Err(error) = manager.run(active) {
                    manager.fail(id, error.to_string());
                }
            })
            .map_err(|error| io::Error::other(error.to_string()))?;

        Ok(id)
    }

    pub fn pause(&self, id: Uuid) -> bool {
        let Some(active) = self.active.lock().unwrap().get(&id).cloned() else {
            return false;
        };
        active.controls.paused.store(true, Ordering::SeqCst);
        if let Ok(mut info) = active.info.lock() {
            info.status = DownloadStatus::Paused;
            let snapshot = info.clone();
            drop(info);
            self.emit(DownloadEvent::Progress(snapshot));
        }
        let _ = self.persist();
        true
    }

    pub fn resume(&self, id: Uuid) -> bool {
        let Some(active) = self.active.lock().unwrap().get(&id).cloned() else {
            return false;
        };
        active.controls.paused.store(false, Ordering::SeqCst);
        if let Ok(mut info) = active.info.lock() {
            if info.status == DownloadStatus::Paused {
                info.status = DownloadStatus::Downloading;
                let snapshot = info.clone();
                drop(info);
                self.emit(DownloadEvent::Progress(snapshot));
            }
        }
        let _ = self.persist();
        true
    }

    pub fn cancel(&self, id: Uuid) -> bool {
        let Some(active) = self.active.lock().unwrap().get(&id).cloned() else {
            return false;
        };
        active.controls.cancelled.store(true, Ordering::SeqCst);
        true
    }

    pub fn get(&self, id: Uuid) -> Option<DownloadInfo> {
        self.active
            .lock()
            .unwrap()
            .get(&id)
            .and_then(|d| d.info.lock().ok().map(|i| i.clone()))
    }

    pub fn open_file(&self, id: Uuid) -> io::Result<()> {
        let info = self.get(id).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "download not found"))?;
        open_path(&info.destination)
    }

    pub fn show_in_folder(&self, id: Uuid) -> io::Result<()> {
        let info = self.get(id).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "download not found"))?;
        show_in_folder(&info.destination)
    }

    pub fn remove_history(&self, id: Uuid) -> bool {
        let removed = self.active.lock().unwrap().remove(&id).is_some();
        let _ = self.persist();
        removed
    }

    pub fn list(&self) -> Vec<DownloadInfo> {
        self.active
            .lock()
            .unwrap()
            .values()
            .filter_map(|d| d.info.lock().ok().map(|i| i.clone()))
            .collect()
    }

    fn run(&self, active: Arc<ActiveDownload>) -> io::Result<()> {
        let id = active.info.lock().unwrap().id;
        let runtime = Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(self.download(active))
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.persist()?;
        Ok(())
    }

    async fn download(&self, active: Arc<ActiveDownload>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut url = Url::parse(&active.info.lock().unwrap().url)?;
        let destination = active.info.lock().unwrap().destination.clone();
        let partial = destination.with_extension(format!(
            "{}part",
            destination.extension().and_then(|e| e.to_str()).map(|e| format!("{e}.")).unwrap_or_default()
        ));

        let mut redirects = 0usize;

        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();

        let client: Client<_, http_body_util::Full<hyper::body::Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        loop {
            if redirects > MAX_REDIRECTS {
                return Err("too many redirects".into());
            }

            self.set_status(&active, DownloadStatus::Downloading);

            let destination = active.info.lock().unwrap().destination.clone();
            let partial = destination.with_extension(format!(
                "{}part",
                destination.extension().and_then(|e| e.to_str()).map(|e| format!("{e}.")).unwrap_or_default()
            ));
            let existing = partial.metadata().map(|m| m.len()).unwrap_or(0);

            // Resume an interrupted transfer when the server supports byte ranges.
            let mut request_builder = Request::builder()
                .method("GET")
                .uri(url.as_str())
                .header(header::ACCEPT, HeaderValue::from_static("*/*"))
                .header(header::USER_AGENT, HeaderValue::from_static("BumbleBee/1.0"));
            if existing > 0 {
                request_builder = request_builder.header(header::RANGE, format!("bytes={existing}-"));
            }
            let mut response = client
                .request(request_builder.body(http_body_util::Full::new(hyper::body::Bytes::new()))?)
                .await?;

            if response.status().is_redirection() {
                let Some(location) = response.headers().get(header::LOCATION) else {
                    return Err("redirect response has no Location header".into());
                };
                url = url.join(location.to_str()?)?;
                redirects += 1;
                continue;
            }

            if !response.status().is_success() {
                return Err(format!("HTTP {}", response.status()).into());
            }

            let header_filename = response
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_content_disposition_filename);

            if let Some(name) = header_filename {
                let safe = sanitize_filename(&name);
                if !safe.is_empty() {
                    let new_destination = self.root.join(unique_filename(&self.root, &safe));
                    let mut info = active.info.lock().unwrap();
                    info.filename = new_destination
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned();
                    info.destination = new_destination;
                }
            }

            let destination = active.info.lock().unwrap().destination.clone();
            let partial = destination.with_extension(format!(
                "{}part",
                destination.extension().and_then(|e| e.to_str()).map(|e| format!("{e}.")).unwrap_or_default()
            ));
            let existing = partial.metadata().map(|m| m.len()).unwrap_or(0);

            // A server that ignores Range forces a clean restart.
            let append = existing > 0 && response.status() == http::StatusCode::PARTIAL_CONTENT;            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(!append)
                .append(append)
                .open(&partial)?;
            let total = response
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(|v| v.saturating_add(existing));

            {
                let mut info = active.info.lock().unwrap();
                info.total_bytes = total;
                info.downloaded_bytes = existing;
            }

            let mut downloaded = existing;
            let mut last_update = Instant::now();
            let mut last_bytes = downloaded;

            while let Some(frame) = response.body_mut().frame().await {
                if active.controls.cancelled.load(Ordering::SeqCst) {
                    drop(file);
                    let _ = fs::remove_file(&partial);
                    self.finish_cancelled(&active);
                    return Ok(());
                }

                while active.controls.paused.load(Ordering::SeqCst) {
                    if active.controls.cancelled.load(Ordering::SeqCst) {
                        drop(file);
                        let _ = fs::remove_file(&partial);
                        self.finish_cancelled(&active);
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }

                let frame = frame?;
                let Some(data) = frame.data_ref() else {
                    continue;
                };

                file.write_all(data)?;
                downloaded += data.len() as u64;

                {
                    let mut info = active.info.lock().unwrap();
                    info.downloaded_bytes = downloaded;
                    info.status = DownloadStatus::Downloading;
                }

                if last_update.elapsed() >= Duration::from_millis(250) {
                    let snapshot = active.info.lock().unwrap().clone();
                    self.emit(DownloadEvent::Progress(snapshot));
                    let elapsed = last_update.elapsed().as_secs_f64();
                    let speed = if elapsed > 0.0 {
                        Some(((downloaded.saturating_sub(last_bytes)) as f64 / elapsed) as u64)
                    } else { None };
                    if let Some(speed) = speed {
                        active.info.lock().unwrap().speed_bytes_per_second = Some(speed);
                    }
                    last_update = Instant::now();
                    last_bytes = downloaded;
                }
            }

            file.flush()?;
            file.sync_all()?;
            drop(file);

            fs::rename(&partial, &destination)?;

            let hash = sha256_file(&destination)?;
            {
                let mut info = active.info.lock().unwrap();
                info.downloaded_bytes = downloaded;
                info.total_bytes = Some(downloaded);
                info.status = DownloadStatus::Completed;
                info.sha256 = Some(hash);
            }

            let snapshot = active.info.lock().unwrap().clone();
            self.emit(DownloadEvent::Completed(snapshot));
            return Ok(());
        }
    }

    fn set_status(&self, active: &Arc<ActiveDownload>, status: DownloadStatus) {
        if let Ok(mut info) = active.info.lock() {
            info.status = status;
        }
        let _ = self.persist();
    }

    fn finish_cancelled(&self, active: &Arc<ActiveDownload>) {
        if let Ok(mut info) = active.info.lock() {
            info.status = DownloadStatus::Cancelled;
            let snapshot = info.clone();
            drop(info);
            self.emit(DownloadEvent::Cancelled(snapshot));
        }
        let _ = self.persist();
    }

    fn fail(&self, id: Uuid, error: String) {
        if let Some(active) = self.active.lock().unwrap().get(&id).cloned() {
            if let Ok(mut info) = active.info.lock() {
                info.status = DownloadStatus::Failed;
                info.error = Some(error);
                let snapshot = info.clone();
                drop(info);
                self.emit(DownloadEvent::Failed(snapshot));
            }
            let _ = self.persist();
        }
    }

    fn emit(&self, event: DownloadEvent) {
        let listeners = self.listeners.lock().unwrap().clone();
        for listener in listeners {
            listener(event.clone());
        }
    }

    fn load_state(&self) -> io::Result<()> {
        if !self.state_file.exists() { return Ok(()); }
        let bytes = fs::read(&self.state_file)?;
        let entries: Vec<DownloadInfo> = serde_json::from_slice(&bytes).unwrap_or_default();
        let mut active = self.active.lock().unwrap();
        for mut info in entries {
            if matches!(info.status, DownloadStatus::Downloading | DownloadStatus::Queued | DownloadStatus::Paused) {
                let partial = info.destination.with_extension(format!("{}part", info.destination.extension().and_then(|e| e.to_str()).map(|e| format!("{e}. ")).unwrap_or_default().trim_end()));
                if partial.exists() {
                    info.status = DownloadStatus::Paused;
                    info.downloaded_bytes = partial.metadata().map(|m| m.len()).unwrap_or(0);
                } else {
                    info.status = DownloadStatus::Failed;
                    info.error = Some("Interrupted download has no partial file".into());
                }
            }
            let id = info.id;
            active.insert(id, Arc::new(ActiveDownload { info: Mutex::new(info), controls: Controls::default() }));
        }
        Ok(())
    }

    pub fn resume_interrupted(&self, id: Uuid) -> bool {
        let Some(active) = self.active.lock().unwrap().get(&id).cloned() else { return false; };
        if !matches!(active.info.lock().unwrap().status, DownloadStatus::Paused | DownloadStatus::Failed) { return false; }
        active.controls.cancelled.store(false, Ordering::SeqCst);
        active.controls.paused.store(false, Ordering::SeqCst);
        if let Ok(mut info) = active.info.lock() { info.status = DownloadStatus::Queued; info.error = None; }
        let manager = self.clone();
        let _ = thread::Builder::new().name(format!("bumble-bee-download-resume-{id}")).spawn(move || {
            if let Err(error) = manager.run(active) { manager.fail(id, error.to_string()); }
        });
        true
    }
    fn persist(&self) -> io::Result<()> {
        let state: Vec<DownloadInfo> = self.list();
        let temporary = self.state_file.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&state)?;
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, &self.state_file)?;
        Ok(())
    }
}

fn filename_from_url(url: &Url) -> String {
    url.path_segments()
        .and_then(|mut s| s.next_back())
        .filter(|s| !s.is_empty())
        .map(sanitize_filename)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "download".to_string())
}

fn sanitize_filename(input: &str) -> String {
    let mut output = input
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect::<String>()
        .trim()
        .trim_end_matches('.')
        .to_string();

    // Prevent Windows device names and hidden path traversal tricks.
    let upper = output.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL"
            | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9"
            | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9"
    ) {
        output.insert(0, '_');
    }

    if output.is_empty() {
        "download".to_string()
    } else {
        output.chars().take(240).collect()
    }
}

fn unique_filename(root: &Path, filename: &str) -> String {
    let path = root.join(filename);
    if !path.exists() {
        return filename.to_string();
    }

    let stem = Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("download");
    let extension = Path::new(filename)
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| format!(".{s}"))
        .unwrap_or_default();

    for n in 1..=9999 {
        let candidate = format!("{stem} ({n}){extension}");
        if !root.join(&candidate).exists() {
            return candidate;
        }
    }

    format!("{stem}-{}{}", Uuid::new_v4(), extension)
}

pub fn parse_content_disposition_filename(value: &str) -> Option<String> {
    let mut fallback = None;

    for part in value.split(';').skip(1) {
        let part = part.trim();
        let (key, raw) = part.split_once('=')?;
        let key = key.trim().to_ascii_lowercase();
        let raw = raw.trim().trim_matches('"');

        if key == "filename*" {
            if let Some((_, encoded)) = raw.split_once("''") {
                if let Ok(decoded) = percent_encoding::percent_decode_str(encoded).decode_utf8() {
                    return Some(decoded.into_owned());
                }
            }
        } else if key == "filename" {
            fallback = Some(raw.to_string());
        }
    }

    fallback
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; BUFFER_SIZE];

    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_windows_paths() {
        assert_eq!(sanitize_filename("../secret.txt"), ".._secret.txt");
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename("hello?.txt"), "hello_.txt");
    }

    #[test]
    fn avoids_collisions() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("file.txt"), b"x").unwrap();
        assert_eq!(unique_filename(dir.path(), "file.txt"), "file (1).txt");
    }

    #[test]
    fn parses_content_disposition() {
        assert_eq!(
            parse_content_disposition_filename(
                r#"attachment; filename="report.pdf"; filename*=UTF-8''report%20final.pdf"#
            ),
            Some("report final.pdf".to_string())
        );
    }
}


fn open_path(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "windows")]
    { std::process::Command::new("cmd").args(["/C", "start", "", &path.to_string_lossy()]).spawn()?.wait()?; }
    #[cfg(target_os = "macos")]
    { std::process::Command::new("open").arg(path).spawn()?.wait()?; }
    #[cfg(all(unix, not(target_os = "macos")))]
    { std::process::Command::new("xdg-open").arg(path).spawn()?.wait()?; }
    Ok(())
}

fn show_in_folder(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "windows")]
    { std::process::Command::new("explorer").arg("/select,").arg(path).spawn()?; }
    #[cfg(target_os = "macos")]
    { std::process::Command::new("open").arg("-R").arg(path).spawn()?; }
    #[cfg(all(unix, not(target_os = "macos")))]
    { std::process::Command::new("xdg-open").arg(path.parent().unwrap_or(path)).spawn()?; }
    Ok(())
}
