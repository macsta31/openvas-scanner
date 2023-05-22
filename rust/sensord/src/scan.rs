use std::{env, sync::PoisonError};

/// The result of a fetch operation
pub type FetchResult = (models::Status, Vec<models::Result>);

impl From<osp::Error> for Error {
    fn from(value: osp::Error) -> Self {
        Self::Unexpected(format!("{value:?}"))
    }
}

#[derive(Debug, Clone)]
/// OSPD wrapper, is used to utilize ospd
pub struct OSPDWrapper {
    /// Path to the socket
    socket: String,
}

#[derive(Debug)]
pub enum Error {
    Unexpected(String),
    Poisoned,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Self::Poisoned
    }
}

impl OSPDWrapper {
    /// Creates a new instance of OSPDWrapper
    pub fn new(socket: String) -> Self {
        Self { socket }
    }

    /// Creates a new instance of OSPDWrapper from the environment
    pub fn from_env() -> Self {
        let socket = env::var("OSPD_SOCKET")
            .ok()
            .unwrap_or_else(|| "/run/ospd/ospd-openvas.sock".to_string());
        Self::new(socket)
    }
}

/// Starts a scan
pub trait ScanStarter {
    /// Starts a scan
    fn start_scan<'a>(&'a self, progress: &'a Progress) -> Result<(), Error>;
}

/// Stops a scan
pub trait ScanStopper {
    /// Stops a scan
    fn stop_scan(&self, progress: &Progress) -> Result<(), Error>;
}

/// Deletes a scan
pub trait ScanDeleter {
    fn delete_scan(&self, progress: &Progress) -> Result<(), Error>;
}

pub trait ScanResultFetcher {
    /// Fetches the results of a scan and combines the results with response
    fn fetch_results(&self, id: &Progress) -> Result<FetchResult, Error>;
}

impl ScanStarter for OSPDWrapper {
    fn start_scan(&self, progress: &Progress) -> Result<(), Error> {
        osp::start_scan(&self.socket, &progress.scan)
            .map_err(Error::from)
            .map(|_| ())
    }
}

impl ScanStopper for OSPDWrapper {
    fn stop_scan(&self, progress: &Progress) -> Result<(), Error> {
        osp::stop_scan(&self.socket, progress.scan.scan_id.as_ref().unwrap())
            .map_err(Error::from)
            .map(|_| ())
    }
}

impl ScanDeleter for OSPDWrapper {
    fn delete_scan(&self, progress: &Progress) -> Result<(), Error> {
        osp::delete_scan(&self.socket, progress.scan.scan_id.as_ref().unwrap())
            .map_err(Error::from)
            .map(|_| ())
    }
}

impl ScanResultFetcher for OSPDWrapper {
    fn fetch_results(&self, progress: &Progress) -> Result<FetchResult, Error> {
        osp::get_delete_scan_results(&self.socket, progress.id())
            .map(|r| (r.clone().into(), r.into()))
            .map_err(Error::from)
    }
}

#[derive(Clone, Debug, Default)]
/// Contains the progress of a scan.
///
/// It is used to keep track of the scan status and results.
/// As scan is in progress as long as `is_done` function of status does not return true.
pub struct Progress {
    /// The scan that is being tracked
    pub scan: models::Scan,
    /// The status of the scan
    pub status: models::Status,
    /// The results of the scan
    pub results: Vec<models::Result>,
}

impl Progress {
    /// Appends the results of a fetch operation to the progress and updates the status.
    pub(crate) fn append_results(&mut self, fr: FetchResult) {
        let (status, results) = fr;
        tracing::trace!("Set status: {:?}", status);
        self.status = status;
        self.results.extend(results);
    }

    pub fn id(&self) -> &str {
        match self.scan.scan_id.as_ref() {
            Some(s) => s,
            None => "",
        }
    }
}

impl From<models::Scan> for Progress {
    fn from(scan: models::Scan) -> Self {
        Self {
            scan,
            status: models::Status::default(),
            results: Vec::new(),
        }
    }
}
