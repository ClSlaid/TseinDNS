use std::net::SocketAddr;

use anyhow::Result;
use quinn::{ClientConfig, Connection, Endpoint, NewConnection, OpenBi, RecvStream, SendStream};
use rand::random;
use tokio::sync::mpsc;

use crate::comm::stream::write_packet;
use crate::comm::{Answer, Task};
use crate::protocol::{Packet, PacketError, TransactionError};

pub struct QuicForwarder {
    rec: mpsc::UnboundedReceiver<Task>,
    connection: QuicManager,
}

impl QuicForwarder {
    pub async fn try_new(
        rec: mpsc::UnboundedReceiver<Task>,
        endpoint: quinn::Endpoint,
        domain: &'static str,
        addr: SocketAddr,
    ) -> Result<Self> {
        tracing::info!(
            "establishing quic connection to quic://{}, statically configured as {}",
            domain,
            addr
        );
        let connection = QuicManager::try_build(endpoint, domain, addr).await?;

        Ok(Self { rec, connection })
    }

    pub async fn run(mut self) -> Result<()> {
        tracing::info!("forward task is running");
        let checkers = futures::stream::FuturesUnordered::new();
        let remote = self.connection.remote_address();
        while let Some(task) = self.rec.recv().await {
            let Task::Query(q, ans_to) = task;
            tracing::info!("forwarding new task from transaction layer.");
            let (mut quic_send, mut quic_recv) = self.connection.open_bi().await;
            let id = random::<u16>();
            let packet = Packet::new_query(id, q);
            let checker = tokio::spawn(async move {
                let r = Packet::parse_stream(&mut quic_recv).await;
                tracing::debug!("received response {:?} on quic stream", r);
                if let Err(..) = r {
                    let TransactionError { id, error } = r.unwrap_err();
                    match error {
                        PacketError::ServFail => {
                            tracing::debug!(
                                "connection closed on stream {} against {}",
                                quic_recv.id(),
                                remote
                            );
                        }
                        e => {
                            let _ = ans_to.send(Answer::Error(e));
                        }
                    }
                    return;
                }
                let packet = r.unwrap();
                tracing::debug!("get answer from upstream: {:?}", packet);
                for ans in packet.answers {
                    let _ = ans_to.send(Answer::Answer(ans));
                }
                for ns in packet.authorities {
                    let _ = ans_to.send(Answer::NameServer(ns));
                }
                for addi in packet.additions {
                    let _ = ans_to.send(Answer::Additional(addi));
                }
            });
            checkers.push(checker);
            let _ = write_packet(&mut quic_send, packet.clone());
            tracing::debug!("packet {:?} sent to quic://{}", packet, remote);
            let _ = quic_send.finish().await;
        }
        for checker in checkers {
            let _ = tokio::join!(checker);
        }
        Ok(())
    }
}

struct QuicManager {
    endpoint: Endpoint,
    addr: SocketAddr,
    domain: String,
    connection: Connection,
}

impl QuicManager {
    pub async fn try_build(
        endpoint: Endpoint,
        remote_domain: &'static str,
        remote_addr: SocketAddr,
    ) -> Result<Self> {
        let conn = endpoint
            .connect(remote_addr, remote_domain)
            .expect("cannot initiate QUIC connection")
            .await?;
        let NewConnection { connection, .. } = conn;
        Ok(Self {
            endpoint,
            addr: remote_addr,
            domain: String::from(remote_domain),
            connection,
        })
    }

    async fn reconnect(&mut self) -> Result<()> {
        let conn = self
            .endpoint
            .connect(self.addr, self.domain.as_str())
            .expect("cannot initiate QUIC connection")
            .await?;
        let NewConnection { connection, .. } = conn;
        self.connection = connection;
        Ok(())
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    pub async fn open_bi(&mut self) -> (SendStream, RecvStream) {
        let r = self.connection.open_bi().await;
        if r.is_err() {
            tracing::debug!("QUIC connection lost, reconnecting...");
            self.reconnect().await.unwrap();
            self.connection.open_bi().await.unwrap()
        } else {
            r.unwrap()
        }
    }
}
