use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot::error::TryRecvError;
use tokio::sync::{mpsc, oneshot};

use crate::comm::{Answer, Task};
use crate::protocol::{Packet, PacketError, TransactionError};

use super::{stream_fail, write_packet};

pub enum Message {
    Update(SocketAddr),
    ShutDown(SocketAddr),
}

pub(super) struct Worker<S>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
{
    client: SocketAddr,
    stream: S,
    task_sender: mpsc::UnboundedSender<Task>,
    m_sender: mpsc::UnboundedSender<Message>,

    // it does not matter what to send
    // but the state of the receiver matters
    m_receiver: oneshot::Receiver<()>,
}

impl<S> Worker<S>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
{
    pub fn new(
        client: SocketAddr,
        stream: S,
        task_sender: mpsc::UnboundedSender<Task>,
        m_sender: mpsc::UnboundedSender<Message>,
        m_receiver: oneshot::Receiver<()>,
    ) -> Self {
        Self {
            client,
            stream,
            task_sender,
            m_sender,
            m_receiver,
        }
    }

    pub async fn run(self) {
        let client = self.client;
        tracing::debug!("Actor against {} starting...", client);

        let (mut rd, mut wr) = tokio::io::split(self.stream);

        // if the packet from a client failed too many times
        // take caution
        let mut is_suspected = false;

        let updater = self.m_sender;
        let mut checker = self.m_receiver;

        // while still not shut down
        loop {
            match checker.try_recv() {
                Err(TryRecvError::Empty) => {
                    // this worker is still online
                    // update
                    let msg = Message::Update(self.client);
                    let _ = updater.send(msg);
                }
                _ => {
                    // this worker is scheduled to close
                    // quit normally
                    break;
                }
            }

            let read = Packet::parse_stream(&mut rd).await;
            if read.is_err() {
                let err = read.unwrap_err();

                if let TransactionError {
                    id: _,
                    error: PacketError::ServFail,
                } = err
                {
                    // read to end of file in stream
                    // quit normally
                    tracing::trace!("connection from {} reaches its end", client);
                    break;
                }

                tracing::warn!("received malformed data {} from client {}", err, client);

                if stream_fail(&mut wr, err).await.is_err() || is_suspected {
                    // stream is closed by peer or the suspected client send corrupted message again
                    // quit directly
                    tracing::warn!(
                        "actor against {} quit due to corrupted data or connection problems",
                        client
                    );
                    let msg = Message::ShutDown(self.client);
                    let _ = updater.send(msg);
                    return;
                }
                if !is_suspected {
                    is_suspected = true
                }
                continue;
            }

            let packet = read.unwrap();
            if !packet.is_query() {
                let id = packet.get_id();
                let error = PacketError::FormatError;
                let failure = Packet::new_failure(id, error);
                if write_packet(&mut wr, failure).await.is_err() || is_suspected {
                    // stream is closed by peer or the suspected client send malformed data again
                    // quit directly
                    tracing::warn!(
                        "actor against {} quit due to malformed data or connection problems",
                        client
                    );
                    let msg = Message::ShutDown(self.client);
                    let _ = updater.send(msg);
                    return;
                }
                continue;
            }

            // forgive the client
            is_suspected = false;

            let query = packet.question.clone().unwrap();
            let (ask, mut answer) = mpsc::unbounded_channel();
            let task = Task::Query(query.clone(), ask);
            let _ = self.task_sender.send(task);

            let mut answers = vec![];
            let mut auths = vec![];
            let mut additionals = vec![];
            while let Some(ans) = answer.recv().await {
                match ans {
                    Answer::Error(error) => {
                        let id = Some(packet.get_id());
                        let err = TransactionError { id, error };
                        if stream_fail(&mut wr, err).await.is_err() {
                            // stream is closed by peer
                            // quit directly
                            tracing::warn!(
                                "actor against {} quit due to connection problems",
                                client
                            );
                            let msg = Message::ShutDown(client);
                            let _ = updater.send(msg);
                            return;
                        }
                        break;
                    }
                    Answer::Answer(a) => {
                        answers.push(a);
                    }
                    Answer::NameServer(n) => {
                        auths.push(n);
                    }
                    Answer::Additional(a) => {
                        additionals.push(a);
                    }
                }
            }
            let mut packet = Packet::new_plain_answer(packet.get_id());
            packet.set_question(query);
            packet.set_answers(answers);
            packet.set_authorities(auths);
            packet.set_addtionals(additionals);
            if write_packet(&mut wr, packet).await.is_err() {
                // stream is closed by peer,
                // quit directly
                tracing::warn!("actor against {} quit due to connection problems", client);
                let msg = Message::ShutDown(client);
                let _ = updater.send(msg);
                return;
            }
        }
        let msg = Message::ShutDown(client);
        let _ = updater.send(msg);
        tracing::debug!("actor against {} shutdown", client);
    }
}

impl<S: 'static> Worker<S>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
{
    pub fn serve(
        stream: S,
        client: SocketAddr,
        task_sender: mpsc::UnboundedSender<Task>,
        msg_sender: mpsc::UnboundedSender<Message>,
    ) -> oneshot::Sender<()> {
        let (sender, receiver) = oneshot::channel();
        let worker = Self::new(client, stream, task_sender, msg_sender, receiver);
        tokio::spawn(async move { worker.run().await });
        sender
    }
}
