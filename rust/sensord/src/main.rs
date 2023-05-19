mod config;
mod controller;
mod feed;
mod request;
mod response;
mod scan;
mod tls;
use hyper::server::conn::AddrIncoming;
use hyper::Server;


use crate::controller::ContextBuilder;
use crate::scan::OSPDWrapper;
use std::sync::Arc;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    let config = config::Config::load();
    tracing::info!("using: \n{}", config);
    let rc = config.ospd.result_check_interval;
    let fc = (config.feed.path.clone(), config.feed.check_interval);
    let scanner = OSPDWrapper::from_env();
    let ctx = ContextBuilder::new()
        .result_config(rc)
        .feed_config(fc)
        .scanner(scanner)
        .build();
    let controller = Arc::new(ctx);
    let addr = config.listener.address;
    let incoming = AddrIncoming::bind(&addr)?;
    let addr = incoming.local_addr();

    if let Some(tlsc) = tls::tls_config(&config)? {
        let make_svc = crate::controller::make_svc!(&controller);
        let server = Server::builder(tls::TlsAcceptor::new(tlsc, incoming)).serve(make_svc);
        tracing::info!("listening on https://{}", addr);
        server.await?;
    } else {
        let make_svc = crate::controller::make_svc!(&controller);
        let server = Server::builder(incoming).serve(make_svc);
        tracing::info!("listening on http://{}", addr);
        server.await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hyper::{Body, Method, Request};

    use super::*;
    use crate::controller::*;
    #[tokio::test]
    async fn contains_version() {
        let controller = Arc::new(Context::default());
        let req = Request::builder()
            .method(Method::HEAD)
            .body(Body::empty())
            .unwrap();
        let resp = entrypoint(req, Arc::clone(&controller)).await.unwrap();
        assert_eq!(resp.headers().get("version").unwrap(), "");
        assert_eq!(resp.headers().get("authentication").unwrap(), "");
    }
    #[tokio::test]
    async fn add_scan() {
        let scan: models::Scan = models::Scan::default();
        let controller = Arc::new(Context::default());
        let req = Request::builder()
            .uri("/scans")
            .method(Method::POST)
            .body(serde_json::to_string(&scan).unwrap().into())
            .unwrap();
        let resp = entrypoint(req, Arc::clone(&controller)).await.unwrap();
        assert_eq!(resp.status(), hyper::StatusCode::CREATED);
        let resp = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let resp = String::from_utf8(resp.to_vec()).unwrap();
        let id = resp.trim_matches('"');
        assert_eq!(uuid::Uuid::parse_str(id).unwrap().to_string(), id);

        let req = Request::builder()
            .uri(format!("/scans/{id}"))
            .method(Method::GET)
            .body(serde_json::to_string(&scan).unwrap().into())
            .unwrap();
        let resp = entrypoint(req, Arc::clone(&controller)).await.unwrap();
        let resp = hyper::body::to_bytes(resp.into_body()).await.unwrap();

        let resp = serde_json::from_slice::<models::Scan>(&resp).unwrap();

        let scan: models::Scan = models::Scan {
            scan_id: Some(id.to_string()),
            ..Default::default()
        };
        assert_eq!(resp, scan);
    }
}
