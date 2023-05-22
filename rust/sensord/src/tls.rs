use core::task::{Context, Poll};
use futures_util::{ready, Future};
use hyper::server::accept::Accept;
use hyper::server::conn::{AddrIncoming, AddrStream};
use rustls::server::{AllowAnyAuthenticatedClient, NoClientAuth};
use rustls::RootCertStore;
use rustls_pemfile::{read_one, Item};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use std::{fs, io};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::ServerConfig;

enum State {
    Handshaking(tokio_rustls::Accept<AddrStream>),
    Streaming(tokio_rustls::server::TlsStream<AddrStream>),
}

// tokio_rustls::server::TlsStream doesn't expose constructor methods,
// so we have to TlsAcceptor::accept and handshake to have access to it
// TlsStream implements AsyncRead/AsyncWrite handshaking tokio_rustls::Accept first
pub struct TlsStream {
    state: State,
}

impl TlsStream {
    fn new(stream: AddrStream, config: Arc<ServerConfig>) -> TlsStream {
        let accept = tokio_rustls::TlsAcceptor::from(config).accept(stream);
        TlsStream {
            state: State::Handshaking(accept),
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_read(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_write(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
    incoming: AddrIncoming,
}

impl TlsAcceptor {
    pub fn new(config: Arc<ServerConfig>, incoming: AddrIncoming) -> TlsAcceptor {
        TlsAcceptor { config, incoming }
    }
}

impl Accept for TlsAcceptor {
    type Conn = TlsStream;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
            Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(sock, pin.config.clone())))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

pub fn tls_config(
    config: &crate::config::Config,
) -> Result<Option<Arc<ServerConfig>>, Box<dyn std::error::Error + Send + Sync>> {
    match load_certs(&config.tls.certs) {
        Ok(certs) => {
            let key = load_private_key(&config.tls.key)?;
            let verifier = {
                let client_certs: Vec<PathBuf> = std::fs::read_dir(&config.tls.client_certs)?
                    .filter_map(|entry| {
                        let entry = entry.ok()?;
                        let file_type = entry.file_type().ok()?;
                        if file_type.is_file() {
                            Some(entry.path())
                        } else {
                            None
                        }
                    })
                    .collect();
                if client_certs.is_empty() {
                    tracing::info!(
                        "no client certs found, starting without certificate based client auth"
                    );
                    NoClientAuth::boxed()
                } else {
                    tracing::info!(
                        "client certs found, starting with certificate based client auth"
                    );
                    let mut client_auth_roots = RootCertStore::empty();
                    for root in client_certs.iter().flat_map(load_certs).flatten() {
                        client_auth_roots.add(&root)?;
                    }
                    AllowAnyAuthenticatedClient::new(client_auth_roots).boxed()
                }
            };

            let mut cfg = rustls::ServerConfig::builder()
                .with_safe_defaults()
                //.with_client_cert_verifier()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| error(format!("{}", e)))?;
            // Configure ALPN to accept HTTP/2, HTTP/1.1, and HTTP/1.0 in that order.
            cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
            Ok(Some(std::sync::Arc::new(cfg)))
        }
        Err(e) => {
            tracing::trace!("failed to load TLS certificates: {}", e);
            Ok(None)
        }
    }
}

pub fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}
// Load public certificate from file.
pub fn load_certs<P>(filename: &P) -> io::Result<Vec<rustls::Certificate>>
where
    P: AsRef<Path> + std::fmt::Debug,
{
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {:?}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|_| error("failed to load certificate".into()))?;
    Ok(certs.into_iter().map(rustls::Certificate).collect())
}

// Load private key from file.
pub fn load_private_key<P>(filename: &P) -> io::Result<rustls::PrivateKey>
where
    P: AsRef<Path> + std::fmt::Debug,
{
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {:?}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    let mut keys = Vec::<Vec<u8>>::new();
    loop {
        match read_one(&mut reader)? {
            None => break,
            Some(Item::RSAKey(key)) => keys.push(key),
            Some(Item::PKCS8Key(key)) => keys.push(key),
            Some(Item::ECKey(key)) => keys.push(key),
            _ => {}
        }
    }
    if keys.len() != 1 {
        return Err(error("expected a single private key".into()));
    }

    Ok(rustls::PrivateKey(keys[0].clone()))
}
