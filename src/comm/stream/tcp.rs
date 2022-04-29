use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};

use super::service::Listener;
use super::Service;

pub type TcpService = Service<TcpListener>;

#[async_trait]
impl Listener for TcpListener {
    type S = TcpStream;

    fn name(&self) -> &'static str {
        "tcp"
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.local_addr()
    }

    async fn accept(&self) -> std::io::Result<(Self::S, SocketAddr)> {
        self.accept().await
    }
}
