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
        .api_key(config.endpoints.key.clone())
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

