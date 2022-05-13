use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};

use super::service::Listener;
use super::Service;

pub type TcpService = Service<TcpListener>;

#[async_trait]
impl Listener for TcpListener {
    type R = ReadHalf<TcpStream>;
    type W = WriteHalf<TcpStream>;

    fn name(&self) -> &'static str {
        "tcp"
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.local_addr()
    }

    async fn acquire(&mut self) -> std::io::Result<((Self::R, Self::W), SocketAddr)> {
        let (s, client) = self.accept().await?;
        let split = tokio::io::split(s);
        Ok((split, client))
    }
}
