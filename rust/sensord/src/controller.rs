use std::{
    collections::HashMap,
    fmt::Display,
    sync::{Arc, RwLock}, path::PathBuf,
};

use hyper::{Body, Method, Request, Response};

use crate::{
    response,
    scan::{Error, ScanDeleter, ScanResultFetcher, ScanStarter, ScanStopper},
};

#[derive(Debug, Clone)]
pub struct NoScanner;
#[derive(Debug, Clone)]
pub struct Scanner<S>(S);

#[derive(Debug, Clone)]
pub struct ResultContext(std::time::Duration);

impl From<std::time::Duration> for ResultContext {
    fn from(d: std::time::Duration) -> Self {
        Self(d)
    }
}

#[derive(Debug, Clone)]
pub struct FeedContext {
    path: PathBuf,
    verify_interval: std::time::Duration,
}

impl From<(PathBuf, std::time::Duration)> for FeedContext {
    fn from((path, verify_interval): (PathBuf, std::time::Duration)) -> Self {
        Self {
            path,
            verify_interval,
        }
    }
}

impl From<(&str, std::time::Duration)> for FeedContext {
    fn from((path, verify_interval): (&str, std::time::Duration)) -> Self {
        (PathBuf::from(path), verify_interval).into()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ContextBuilder<S, T> {
    scanner: T,
    result_config: Option<ResultContext>,
    feed_config: Option<FeedContext>,
    marker: std::marker::PhantomData<S>,
}

impl<S> ContextBuilder<S, NoScanner> {
    pub fn new() -> Self {
        Self {
            scanner: NoScanner,
            result_config: None,
            feed_config: None,
            marker: std::marker::PhantomData,
        }
    }
}

impl<S, T> ContextBuilder<S, T> {
    pub fn result_config(mut self, config: impl Into<ResultContext>) -> Self {
        self.result_config = Some(config.into());
        self
    }

    pub fn feed_config(mut self, config: impl Into<FeedContext>) -> Self {
        self.feed_config = Some(config.into());
        self
    }
}

impl<S> ContextBuilder<S, NoScanner>
where
    S: Clone,
{
    pub fn scanner(self, scanner: S) -> ContextBuilder<S, Scanner<S>> {
        let Self {
            result_config,
            feed_config,
            scanner: _,
            marker: _,
        } = self;
        ContextBuilder {
            scanner: Scanner(scanner),
            result_config,
            feed_config,
            marker: std::marker::PhantomData,
        }
    }
}

impl<S> ContextBuilder<S, Scanner<S>> {
    pub fn build(self) -> Context<S> {
        Context {
            scanner: self.scanner.0,
            response: Default::default(),
            scans: Default::default(),
            oids: Default::default(),
            result_config: self.result_config,
            feed_config: self.feed_config,
        }
    }
}

#[derive(Debug)]
/// The context of the application
///
/// It contains the scanner and the scans that are being tracked.
pub struct Context<S> {
    /// The scanner that is used to start, stop and fetch results of scans.
    scanner: S,
    response: response::Response,
    /// The scans that are being tracked.
    ///
    /// It is locked to allow concurrent access, usually the results are updated
    /// with a background task and appended to the progress of the scan.
    scans: RwLock<HashMap<String, crate::scan::Progress>>,
    oids: RwLock<(String, Vec<String>)>,
    result_config: Option<ResultContext>,
    feed_config: Option<FeedContext>,
}

#[derive(Debug, Clone, Default)]
pub struct NoOpScanner;

impl ScanStarter for NoOpScanner {
    fn start_scan<'a>(&'a self, _: &'a crate::scan::Progress) -> Result<(), Error> {
        Ok(())
    }
}

impl ScanStopper for NoOpScanner {
    fn stop_scan(&self, _: &crate::scan::Progress) -> Result<(), Error> {
        Ok(())
    }
}

impl ScanDeleter for NoOpScanner {
    fn delete_scan(&self, _: &crate::scan::Progress) -> Result<(), Error> {
        Ok(())
    }
}

impl ScanResultFetcher for NoOpScanner {
    fn fetch_results(
        &self,
        _: &crate::scan::Progress,
    ) -> Result<crate::scan::FetchResult, Error> {
        Ok(Default::default())
    }
}

impl Default for Context<NoOpScanner> {
    fn default() -> Self {
        ContextBuilder::new().scanner(Default::default()).build()
    }
}

/// The supported paths of scannerd
enum KnownPaths {
    /// /scans/{id}
    Scans(Option<String>),
    /// /scans/{id}/results/{result_id}
    ScanResults(String, Option<String>),
    /// /scans/{id}/status
    ScanStatus(String),
    /// /vts
    Vts,
    /// Not supported
    Unknown,
}

impl KnownPaths {
    #[tracing::instrument]
    fn from_path(path: &str) -> Self {
        let mut parts = path.split('/').filter(|s| !s.is_empty());
        match parts.next() {
            Some("scans") => match parts.next() {
                Some(id) => match parts.next() {
                    Some("results") => {
                        KnownPaths::ScanResults(id.to_string(), parts.next().map(|s| s.to_string()))
                    }
                    Some("status") => KnownPaths::ScanStatus(id.to_string()),
                    Some(_) => KnownPaths::Unknown,
                    None => KnownPaths::Scans(Some(id.to_string())),
                },
                None => KnownPaths::Scans(None),
            },
            Some("vts") => KnownPaths::Vts,
            _ => {
                tracing::trace!("Unknown path: {path}");
                KnownPaths::Unknown
            }
        }
    }
}

impl Display for KnownPaths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KnownPaths::Scans(Some(id)) => write!(f, "/scans/{}", id),
            KnownPaths::Scans(None) => write!(f, "/scans"),
            KnownPaths::ScanResults(id, Some(result_id)) => {
                write!(f, "/scans/{}/results/{}", id, result_id)
            }
            KnownPaths::ScanResults(id, None) => write!(f, "/scans/{}/results", id),
            KnownPaths::ScanStatus(id) => write!(f, "/scans/{}/status", id),
            KnownPaths::Unknown => write!(f, "Unknown"),
            KnownPaths::Vts => write!(f, "/vts"),
        }
    }
}

pub fn quit_on_poison<T>() -> T {
    tracing::error!("exit because of poisoned lock");
    std::process::exit(1);
}

/// Is used to call a blocking function and return a response.
///
/// This is necessary as the ospd library is blocking and when blocking calls
/// are made in a tokio the complete thread will be blocked.
///
/// To give tokio the chance to handle the blocking call appropriately it is
/// wrapped within a tokio::task::spawn_blocking call.
///
/// If the thread panics a 500 response is returned.
async fn response_blocking<F>(f: F) -> Result<Response<Body>, Error>
where
    F: FnOnce() -> Result<Response<Body>, Error> + std::marker::Send + 'static,
{
    Ok(match tokio::task::spawn_blocking(f).await {
        Ok(Ok(r)) => r,
        Ok(Err(Error::Poisoned)) => quit_on_poison(),
        Ok(Err(e)) => {
            tracing::warn!("unhandled error: {:?} returning 500", e);
            hyper::Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(hyper::Body::empty())
                .unwrap()
        }
        Err(e) => {
            tracing::warn!("panic {:?}, returning 500", e);
            hyper::Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(hyper::Body::empty())
                .unwrap()
        }
    })
}

/// Is used to handle all incomng requests.
///
/// First it will be checked if a known path is requested and if the method is supported.
/// Than corresponding functions will be called to handle the request.
pub async fn entrypoint<'a, S>(
    req: Request<Body>,
    ctx: Arc<Context<S>>,
) -> Result<Response<Body>, Error>
where
    S: ScanStarter
        + ScanStopper
        + std::marker::Send
        + 'static
        + std::marker::Sync
        + std::fmt::Debug,
{
    use KnownPaths::*;
    let kp = KnownPaths::from_path(req.uri().path());
    tracing::debug!("{} {}", req.method(), kp);
    match (req.method(), kp) {
        (&Method::HEAD, _) => Ok(ctx.response.no_content()),
        (&Method::POST, Scans(None)) => {
            match crate::request::json_request::<models::Scan>(&ctx.response, req).await {
                Ok(mut scan) => {
                    response_blocking(move || {
                        if scan.scan_id.is_none() {
                            scan.scan_id = Some(uuid::Uuid::new_v4().to_string());
                        }
                        let mut scans = ctx.scans.write()?;
                        let id = scan.scan_id.clone().unwrap_or_default();
                        let resp = ctx.response.created(&id);
                        scans.insert(id, crate::scan::Progress::from(scan));
                        Ok(resp)
                    })
                    .await
                }
                Err(resp) => Ok(resp),
            }
        }
        (&Method::POST, Scans(Some(id))) => {
            match crate::request::json_request::<models::ScanAction>(&ctx.response, req).await {
                Ok(action) => {
                    response_blocking(move || {
                        let mut scans = ctx.scans.write()?;
                        // TODO simplify
                        match scans.get_mut(&id) {
                            Some(progress) => {
                                tracing::debug!(
                                    "{}: {}",
                                    progress.scan.scan_id.as_ref().unwrap_or(&"".to_string()),
                                    action.action,
                                );

                                let resp: Result<(), Error> = match action.action {
                                    models::Action::Start => {
                                        if progress.status.status.is_running() {
                                            use models::Phase::*;
                                            let expected = &[Declared, Stopped, Failed, Succeeded];
                                            return Ok(ctx
                                                .response
                                                .not_accepted(&progress.status.status, expected));
                                        }
                                        progress.status.status = models::Phase::Requested;
                                        ctx.scanner.start_scan(progress)
                                    }
                                    models::Action::Stop => ctx.scanner.stop_scan(progress),
                                };
                                // we only start scans that are not running
                                match resp {
                                    Ok(()) => Ok(ctx.response.no_content()),
                                    Err(e) => Ok(ctx.response.internal_server_error(&e)),
                                }
                            }
                            None => Ok(ctx.response.not_found("scans", &id)),
                        }
                    })
                    .await
                }
                Err(resp) => Ok(resp),
            }
        }
        (&Method::GET, Scans(None)) => {
            response_blocking(move || {
                let scans = ctx.scans.read()?;
                Ok(ctx.response.ok(&scans.keys().collect::<Vec<_>>()))
            })
            .await
        }
        (&Method::GET, Scans(Some(id))) => {
            response_blocking(move || {
                let scans = ctx.scans.read()?;
                match scans.get(&id) {
                    Some(prgrs) => Ok(ctx.response.ok(&prgrs.scan)),
                    None => Ok(ctx.response.not_found("scans", &id)),
                }
            })
            .await
        }
        (&Method::GET, ScanStatus(id)) => {
            response_blocking(move || {
                let scans = ctx.scans.read()?;
                match scans.get(&id) {
                    Some(prgrs) => Ok(ctx.response.ok(&prgrs.status)),
                    None => Ok(ctx.response.not_found("scans/status", &id)),
                }
            })
            .await
        }
        (&Method::DELETE, Scans(Some(id))) => {
            response_blocking(move || {
                let mut scans = ctx.scans.write()?;
                match scans.remove(&id) {
                    Some(s) => {
                        if s.status.is_running() {
                            ctx.scanner.stop_scan(&s)?;
                        }
                        Ok(ctx.response.no_content())
                    }
                    None => Ok(ctx.response.not_found("scans", &id)),
                }
            })
            .await
        }
        (&Method::GET, ScanResults(id, _rid)) => {
            response_blocking(move || {
                let scans = ctx.scans.read()?;
                match scans.get(&id) {
                    Some(prgrs) => Ok(ctx.response.ok(&prgrs.results)),
                    None => Ok(ctx.response.not_found("scans", &id)),
                }
            })
            .await
        }
        (&Method::GET, Vts) => Ok(ctx.response.ok(&ctx.oids)),
        _ => Ok(ctx.response.not_found("path", req.uri().path())),
    }
}

pub mod results {

    use super::*;

    pub async fn fetch<S>(ctx: Arc<Context<S>>)
    where
        S: ScanResultFetcher + std::marker::Send + std::marker::Sync + 'static + std::fmt::Debug,
    {
        if let Some(cfg) = &ctx.result_config {
            let interval = cfg.0;
            tracing::debug!("Starting synchronization loop");
            tokio::task::spawn_blocking(move || loop {
                let ls = match ctx.scans.read() {
                    Ok(ls) => ls,
                    Err(_) => quit_on_poison(),
                };
                let scans = ls.clone();
                drop(ls);
                for (id, prgs) in scans.iter() {
                    if prgs.status.is_done() {
                        tracing::trace!("{id} skipping status = {}", prgs.status.status);
                        continue;
                    }
                    match ctx.scanner.fetch_results(prgs) {
                        Ok(fr) => {
                            tracing::trace!("{id} fetched results");
                            let mut progress = prgs.clone();
                            progress.append_results(fr);
                            let mut ls = match ctx.scans.write() {
                                Ok(ls) => ls,
                                Err(_) => quit_on_poison(),
                            };
                            ls.insert(progress.scan.scan_id.clone().unwrap(), progress);
                            drop(ls);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to fetch results for {id}: {e}");
                        }
                    }
                }
                std::thread::sleep(interval);
            })
            .await
            .unwrap();
        }
    }
}

pub mod vts {
    use crate::feed::FeedIdentifier;

    use super::*;
    pub async fn fetch<S>(ctx: Arc<Context<S>>)
    where
        S: std::marker::Send + std::marker::Sync + 'static,
    {
        if let Some(cfg) = &ctx.feed_config {
            let interval = cfg.verify_interval;
            let path = cfg.path.clone();
            tracing::debug!("Starting VTS synchronization loop");
            tokio::task::spawn_blocking(move || loop {
                let last_hash = match ctx.oids.read() {
                    Ok(vts) => vts.0.clone(),
                    Err(_) => quit_on_poison(),
                };
                let hash = match FeedIdentifier::sumfile_hash(&path) {
                    Ok(h) => h,
                    Err(e) => {
                        tracing::warn!("Failed to compute sumfile hash: {e:?}");
                        "".to_string()
                    }
                };
                if last_hash != hash {
                    tracing::debug!("VTS hash {last_hash} changed {hash}, updating");
                    match FeedIdentifier::from_feed(&path) {
                        Ok(o) => {
                            let mut oids = match ctx.oids.write() {
                                Ok(oids) => oids,
                                Err(_) => quit_on_poison(),
                            };
                            tracing::trace!("VTS hash changed updated (old: {}, new: {})", oids.1.len(), o.len());
                            *oids = (hash, o);
                        }
                        Err(e) => {
                            tracing::warn!("unable to fetch new oids, leaving the old: {e:?}")
                        }
                    };
                }

                std::thread::sleep(interval);
            })
            .await
            .unwrap();
        }
    }
}

macro_rules! make_svc {
    ($controller:expr) => {{
        // start background service
        tokio::spawn(crate::controller::results::fetch(Arc::clone(&$controller)));
        tokio::spawn(crate::controller::vts::fetch(Arc::clone(&$controller)));

        use hyper::service::{make_service_fn, service_fn};
        make_service_fn(|_conn| {
            let controller = Arc::clone($controller);
            async {
                Ok::<_, crate::scan::Error>(service_fn(move |req| {
                    crate::controller::entrypoint(req, Arc::clone(&controller))
                }))
            }
        })
    }};
}

pub(crate) use make_svc;
