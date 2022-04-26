// pub(crate) mod stream;
// pub(crate) mod tcp_stream;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use rand::prelude::random;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, OnceCell, oneshot};
use tokio::time::timeout;
use tracing;

use crate::protocol::{Packet, PacketError, Question, RR, TransactionError};

static TIME_OUT: OnceCell<Duration> = OnceCell::const_new();

async fn get_time_out() -> Duration {
    *TIME_OUT
        .get_or_init(|| async { Duration::from_secs(5) })
        .await
}

#[derive(Debug)]
pub enum Task {
    Query(Question, mpsc::UnboundedSender<Answer>),
}

#[derive(Debug, Clone)]
pub enum Answer {
    Error(PacketError),
    Answer(RR),
    NameServer(RR),
    Additional(RR),
}

#[derive(Clone)]
pub struct Manager {
    // serving port, to downstream
    udp: Arc<UdpSocket>,
    // recursive lookup socket, to upstream
    forward: Arc<UdpSocket>,
}

impl Manager {
    pub fn new(udp: UdpSocket, forward: UdpSocket) -> Manager {
        Manager {
            udp: Arc::new(udp),
            forward: Arc::new(forward),
        }
    }

    pub async fn run_forward(
        self: Arc<Self>,
        mut recur_receiver: mpsc::UnboundedReceiver<Task>,
    ) -> Result<(), std::io::Error> {
        let mp: Arc<Mutex<BTreeMap<u16, oneshot::Sender<Vec<Answer>>>>> =
            Arc::new(Mutex::new(BTreeMap::new()));

        let mp_listener = mp.clone();
        let (buf_sender, mut buf_receiver) = mpsc::channel::<Bytes>(4);

        let s = self.clone();
        tracing::debug!("setting up listener");
        let listening = tokio::spawn(async move {
            // this handle will receive packet from upstream and push them into map
            let mut buf = BytesMut::from(&[0_u8; 1024][..]);
            while let Ok(sz) = s.forward.clone().recv(&mut buf).await {
                if sz < 20 {
                    // malformed packet
                    tracing::debug!(
                        "received malformed packet from upstream, length {}, data: {:?}",
                        sz,
                        buf
                    );
                    continue;
                }
                let rs = Packet::parse_packet(buf.clone().into(), 0);
                match rs {
                    Ok(pkt) => {
                        let id = pkt.get_id();
                        let mp = mp_listener.clone();
                        let answers = pkt
                            .answers
                            .into_iter()
                            .map(Answer::Answer)
                            .chain(pkt.authorities.into_iter().map(Answer::NameServer))
                            .chain(pkt.additions.into_iter().map(Answer::Additional))
                            .collect();
                        {
                            let mut guard = mp.lock().await;
                            if let Some(sender) = guard.remove(&id) {
                                sender.send(answers).unwrap();
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("received failure from upstream: {}", e);
                        // maybe malformed packet or corrupted data
                        // ignore it
                        // if there is a task that corresponds to the packet
                        // the task will gracefully timeout and return back with ServFail
                    }
                }
            }
        });
        let forward_socket = self.forward.clone();
        // sending packet that received from task queue
        let forwarding = tokio::spawn(async move {
            while let Some(packet) = buf_receiver.recv().await {
                forward_socket.send(&packet[..]).await.unwrap();
            }
        });

        let mut checkers = vec![];

        while let Some(task) = recur_receiver.recv().await {
            // Get a task from main, try generate a unique id for it
            let id: u16 = random();
            let Task::Query(query, answer_sender) = task;

            // sending answer between `listening` handle and `checker`
            let (checker_sender, checker_receiver) = oneshot::channel();
            let mp = mp.clone();
            {
                // insert into map before sending packet, to avoid data racing
                let mut guard = mp.lock().await;
                guard.insert(id, checker_sender);
            }

            let packet_sender = buf_sender.clone();
            // recursive look up
            let pkt = Packet::new_query(id, query);
            let buf = pkt.into_bytes();
            packet_sender.send(buf).await.unwrap();
            // check after the packet is sent
            let checker = tokio::spawn(async move {
                let answers = timeout(get_time_out().await, checker_receiver).await;
                if answers.is_err() {
                    // timeout
                    answer_sender
                        .send(Answer::Error(PacketError::ServFail))
                        .unwrap();
                    return;
                }
                let answers = answers.unwrap();
                if answers.is_err() {
                    // sender closed unexpectedly
                    answer_sender
                        .send(Answer::Error(PacketError::ServFail))
                        .unwrap();
                    return;
                }
                let answers = answers.unwrap();
                for answer in answers.into_iter() {
                    answer_sender.send(answer).unwrap();
                }
            });
            checkers.push(checker);
        }
        let (l, f) = tokio::join!(listening, forwarding);
        futures::future::join_all(checkers).await;
        l.unwrap();
        f.unwrap();
        Ok(())
    }

    async fn transaction(
        &self,
        pkt: Packet,
        task_sender: mpsc::UnboundedSender<Task>,
    ) -> Result<Vec<Answer>, TransactionError> {
        let id = Some(pkt.get_id());
        if !pkt.is_query() {
            let err = TransactionError {
                id,
                error: PacketError::ServFail,
            };
            return Err(err);
        }

        let mut rxs = vec![];
        for query in pkt.questions {
            let (a_sender, a_recv) = mpsc::unbounded_channel::<Answer>();
            let task = Task::Query(query, a_sender);
            rxs.push(a_recv);
            task_sender.send(task).unwrap();
        }
        let mut answers = vec![];
        for rx in rxs.iter_mut() {
            let answer = rx.recv().await.unwrap();
            match answer {
                Answer::Error(error) => {
                    let err = TransactionError { id, error };
                    return Err(err);
                }
                answer => answers.push(answer),
            }
        }

        Ok(answers)
    }

    async fn udp_fail(&self, err: TransactionError, client: SocketAddr) {
        let udp = self.udp.clone();
        let TransactionError { id, error } = err;
        let id = id.unwrap_or(0);
        let packet = Packet::new_failure(id, error);
        udp.send_to(&packet.into_bytes(), client).await.unwrap();
    }

    pub async fn run_udp(
        self: Arc<Self>,
        task_sender: mpsc::UnboundedSender<Task>,
    ) -> Result<(), std::io::Error> {
        let s = self.clone();
        loop {
            // receive packet
            let mut packet = BytesMut::from(&[0_u8; 1024][..]);
            let (n, client) = s.udp.recv_from(&mut packet).await?;

            // validate packet
            if n < 12 {
                tracing::debug!("received malformed packet from {}", client);
                tracing::trace!("packet length: {}, data: {:?}", n, packet);
                // ignore
                continue;
            }

            let pkt = match Packet::parse_packet(packet.clone().into(), 0) {
                Ok(pkt) => pkt,
                Err(err) => {
                    let s = s.clone();
                    tokio::spawn(async move {
                        tracing::debug!(
                            "received malformed packet from {} with failure {}",
                            client,
                            err
                        );
                        s.udp_fail(err, client).await;
                    });
                    continue;
                }
            };
            tracing::debug!("received packet from client: {}", client);

            let task_sender = task_sender.clone();

            // spawn a new task to proceed the packet
            let s = s.clone();
            tokio::spawn(async move {
                let id = pkt.get_id();
                let rs = s.transaction(pkt, task_sender).await;
                if rs.is_err() {
                    s.udp_fail(rs.unwrap_err(), client).await;
                    return;
                }
                let answers = rs.unwrap();
                let mut resp = Packet::new_plain_answer(id);
                for ans in answers {
                    match ans {
                        Answer::Error(_) => {
                            eprintln!("wtf?")
                        }
                        Answer::Answer(ans) => resp.add_answer(ans),
                        Answer::NameServer(ns) => resp.add_authority(ns),
                        Answer::Additional(ad) => resp.add_addition(ad),
                    }
                }
                let packet = resp.into_bytes();
                let udp = s.udp.clone();
                udp.send_to(&packet, client).await.unwrap();
            });
        }
    }
}
