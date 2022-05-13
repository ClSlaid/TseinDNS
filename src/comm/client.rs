use std::net::SocketAddr;

use anyhow::Result;
use quinn::NewConnection;
use rand::random;
use tokio::sync::mpsc;

use crate::comm::stream::write_packet;
use crate::comm::{Answer, Task};
use crate::protocol::{Packet, PacketError, TransactionError};

pub struct QuicForwarder {
    rec: mpsc::UnboundedReceiver<Task>,
    connection: quinn::Connection,
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
        let NewConnection { connection, .. } = endpoint.connect(addr, domain)?.await?;

        Ok(Self { rec, connection })
    }

    pub async fn run(mut self) -> Result<()> {
        tracing::info!("forward task is running");
        let checkers = futures::stream::FuturesUnordered::new();
        let remote = self.connection.remote_address();
        while let Some(task) = self.rec.recv().await {
            let Task::Query(q, ans_to) = task;
            tracing::info!("forwarding new task from transaction layer.");
            let (mut quic_send, mut quic_recv) = self
                .connection
                .open_bi()
                .await
                .expect("cannot initiate QUIC stream");
            let id = random::<u16>();
            let packet = Packet::new_query(id, q);
            let checker = tokio::spawn(async move {
                let r = Packet::parse_stream(&mut quic_recv).await;
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
            let _ = write_packet(&mut quic_send, packet);
        }
        for checker in checkers {
            let _ = tokio::join!(checker);
        }
        Ok(())
    }
}
