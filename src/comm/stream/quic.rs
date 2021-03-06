// Copyright (c) 2022 ClSlaid <cailue@bupt.edu.cn>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::net::SocketAddr;

use bytes::Bytes;
use futures::StreamExt;
use quinn::{Incoming, RecvStream, SendStream};
use tokio::{io::AsyncReadExt, sync::mpsc};

use crate::{
    comm::{stream::stream_fail, Answer, Task},
    protocol::{Packet, PacketError, TransactionError},
};

pub struct QuicService {
    listener: Incoming,
    task: mpsc::UnboundedSender<Task>,
}

impl QuicService {
    pub fn new(listener: Incoming, task: mpsc::UnboundedSender<Task>) -> Self {
        Self { listener, task }
    }

    pub async fn run(mut self) {
        let mut futs = futures::stream::FuturesUnordered::new();
        while let Some(conn) = self.listener.next().await {
            let client = conn.remote_address();
            tracing::info!("connection from quic://{}", client);
            let task_sender = self.task.clone();
            let fut = tokio::spawn(async move { client_handler(conn, task_sender).await });
            futs.push(fut);
        }
        // join all
        while !futs.is_empty() {
            let _ = futs.next().await;
        }
    }
}

/// `worker` is a handler for a QUIC `stream`
/// like a tiny `super::worker::Worker` implementation
async fn worker(
    mut recv: RecvStream,
    mut send: SendStream,
    task_sender: mpsc::UnboundedSender<Task>,
    client: SocketAddr,
) {
    let stream_id = send.id().index();
    tracing::debug!("serving stream {} from quic://{}", stream_id, client);

    let mut v = vec![];
    let r = recv.read_buf(&mut v).await;
    let len = match r {
        Ok(l) => l,
        Err(_) => {
            tracing::warn!("failed to read on stream {}", recv.id());
            return;
        }
    };
    tracing::debug!("read {} bytes on stream {}", len, recv.id());
    let pkt = match Packet::parse_packet(Bytes::from(v), 0) {
        Err(TransactionError {
            id: _,
            error: PacketError::ServFail,
        }) => {
            // read to end of file, quit
            tracing::debug!(
                "stream {} from quic:://{} reaches end of file",
                stream_id,
                client
            );
            return;
        }
        Err(e) => {
            // packet got error
            tracing::debug!(
                "stream {} from quic:://{} got malformed data: {}",
                stream_id,
                client,
                e
            );
            let _ = stream_fail(&mut send, e).await.is_err();
            return;
        }
        Ok(pkt) => {
            if !pkt.is_query() {
                let id = pkt.get_id();
                let error = PacketError::FormatError;
                let fail = TransactionError {
                    id: Some(id),
                    error,
                };
                let _ = stream_fail(&mut send, fail).await.is_err();
                return;
            }
            pkt
        }
    };

    let id = pkt.get_id();
    let query = pkt.question.unwrap();
    let (ans_send, mut ans_recv) = mpsc::unbounded_channel();
    let task = Task::Query(query.clone(), ans_send);
    let _ = task_sender.send(task);

    let mut answers = vec![];
    let mut auths = vec![];
    let mut additionals = vec![];
    while let Some(ans) = ans_recv.recv().await {
        match ans {
            Answer::Error(error) => {
                let err = TransactionError {
                    id: Some(id),
                    error,
                };
                let _ = stream_fail(&mut send, err).await.is_err();
                break;
            }
            Answer::Answer(a) => {
                answers.push(a);
            }
            Answer::NameServer(a) => {
                auths.push(a);
            }
            Answer::Additional(a) => {
                additionals.push(a);
            }
        }
    }
    let mut packet = Packet::new_plain_answer(id);
    packet.set_question(query);
    packet.set_answers(answers);
    packet.set_authorities(auths);
    packet.set_addtionals(additionals);

    if send.write_all(&packet.into_bytes()[..]).await.is_err() {
        tracing::warn!(
            "stream {} to quic://{} closed unexpectedly",
            stream_id,
            client
        );
        return;
    }
    let _ = send.finish().await;
    tracing::debug!("stream {} to quic://{} closed", stream_id, client);
}

/// client_handler could be used for handling streams from a specific client.
async fn client_handler(
    conn: quinn::Connecting,
    task_sender: mpsc::UnboundedSender<Task>,
) -> Result<(), quinn::ConnectionError> {
    let quinn::NewConnection {
        connection,
        mut bi_streams,
        ..
    } = conn.await?;
    tracing::debug!(
        "quic connection established: quic://{}",
        connection.remote_address()
    );
    let client = connection.remote_address();
    let mut futs = futures::stream::FuturesUnordered::new();
    while let Some(stream) = bi_streams.next().await {
        let (send, recv) = match stream {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                tracing::warn!(
                    "quic connection closed by peer: quic://{}",
                    connection.remote_address()
                );
                // connection is closed, keeping proceeding futures is meaningless
                // quit directly, but normally.
                return Ok(());
            }
            Err(e) => {
                tracing::warn!("connection to quic://{} closed due to {:?}", client, e);
                // connection is closed, keeping proceeding futures is meaningless
                // quit directly, and return an error.
                return Err(e);
            }
            Ok(s) => s,
        };

        let task_sender = task_sender.clone();
        let worker = tokio::spawn(async move { worker(recv, send, task_sender, client).await });
        futs.push(worker);
    }
    // join all
    while !futs.is_empty() {
        let _ = futs.next().await;
    }
    Ok(())
}
