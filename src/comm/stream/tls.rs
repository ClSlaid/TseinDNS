use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use super::service::Listener;
use super::Service;

pub type TlsService = Service<TlsListener>;

pub struct TlsListener {
    listener: TcpListener,
    tls: TlsAcceptor,
}

impl TlsListener {
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>) -> Self {
        let tls = TlsAcceptor::from(config);
        Self { listener, tls }
    }
}

#[async_trait]
impl Listener for TlsListener {
    type R = ReadHalf<TlsStream<TcpStream>>;
    type W = WriteHalf<TlsStream<TcpStream>>;

    fn name(&self) -> &'static str {
        "tls"
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    async fn acquire(&mut self) -> std::io::Result<((Self::R, Self::W), SocketAddr)> {
        let (s, client) = self.listener.accept().await?;
        let tls = self.tls.accept(s).await?;
        let split = tokio::io::split(tls);
        Ok((split, client))
    }
}
