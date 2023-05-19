mod controller;
mod feed;
mod request;
mod response;
mod scan;
mod tls;
use hyper::server::conn::AddrIncoming;
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;

use crate::controller::ContextBuilder;
use std::sync::Arc;
use std::time::Duration;
// TODO change
use crate::scan::*;

macro_rules! http_server {
    ($addr:expr, $controller:expr) => {{
        let make_svc = crate::controller::make_svc!($controller);
        let addr = $addr;
        let incoming = AddrIncoming::bind(&addr)?;
        let addr = incoming.local_addr();
        let server = Server::builder(incoming).serve(make_svc);

        (server, addr)
    }};
}

macro_rules! mtls_server {
    ($addr:expr, $controller:expr, $credentials:expr) => {{
        let make_svc = crate::controller::make_svc!($controller);
        let (key, scert, ccerts) = $credentials;
        let tls_cfg = {
            // Load public certificate.
            let certs = tls::load_certs(scert)?;
            // Load private key.
            let key = tls::load_private_key(key)?;
            //tls::load_certs(client_root)?
            let roots = ccerts
                .iter()
                .flat_map(|path| tls::load_certs(path))
                .flatten();
            let mut client_auth_roots = RootCertStore::empty();
            for root in roots {
                client_auth_roots.add(&root).unwrap();
            }
            let mut cfg = rustls::ServerConfig::builder()
                .with_safe_defaults()
                //.with_client_cert_verifier(NoClientAuth::boxed())
                .with_client_cert_verifier(
                    AllowAnyAuthenticatedClient::new(client_auth_roots).boxed(),
                )
                .with_single_cert(certs, key)
                .map_err(|e| tls::error(format!("{}", e)))?;
            // Configure ALPN to accept HTTP/2, HTTP/1.1, and HTTP/1.0 in that order.
            cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
            std::sync::Arc::new(cfg)
        };
        let addr = $addr;
        let incoming = AddrIncoming::bind(&addr)?;
        let addr = incoming.local_addr();
        let server = Server::builder(tls::TlsAcceptor::new(tls_cfg, incoming)).serve(make_svc);
        (server, addr)
    }};
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    let rc = Duration::from_secs(1);
    let fc = ("/var/lib/openvas/plugins", Duration::from_secs(60 * 60));
    let scanner = OSPDWrapper::from_env();
    let ctx = ContextBuilder::new()
        .result_config(rc)
        .feed_config(fc)
        .scanner(scanner)
        .build();
    let controller = Arc::new(ctx);
    // For every connection, we must make a `Service` to handle all
    // incoming HTTP requests on said connection.

    let _server_certs = "examples/tls/sample.pem";
    let _server_prv_key = "examples/tls/sample.rsa";
    let _client_roots = &["examples/tls/client_sample.pem"];

    // Build TLS configuration.

    //let server = Server::builder(tls::TlsAcceptor::new(tls_cfg, incoming)).serve(make_svc);

    let (server, addr) = http_server!(([127, 0, 0, 1], 3000).into(), &controller);
    //    let (server, addr) = mtls_server!(
    //        ([127, 0, 0, 1], 3000).into(),
    //        &controller,
    //        (server_prv_key, server_certs, client_roots)
    //    );

    tracing::info!("Listening on {}", addr);

    server.await?;

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
