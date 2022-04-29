use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use super::service::Listener;
use super::Service;

pub type TlsService = Service<TlsOverTcpListener>;

pub struct TlsOverTcpListener {
    listener: TcpListener,
    tls: TlsAcceptor,
}

impl TlsOverTcpListener {
    pub fn new(listener: TcpListener, config: ServerConfig) -> Self {
        let tls = TlsAcceptor::from(Arc::new(config));
        Self { listener, tls }
    }
}

#[async_trait]
impl Listener for TlsOverTcpListener {
    type S = TlsStream<TcpStream>;

    fn name(&self) -> &'static str {
        "tls"
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    async fn accept(&self) -> std::io::Result<(Self::S, SocketAddr)> {
        let (s, client) = self.listener.accept().await?;
        let tls = self.tls.accept(s).await?;
        Ok((tls, client))
    }
}
