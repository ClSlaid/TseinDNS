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

pub use stream::TcpService;

use crate::protocol::{Packet, PacketError, Question, RR, TransactionError};

pub(crate) mod forward;
pub(crate) mod stream;

pub(crate) type TaskMap = Arc<Mutex<BTreeMap<u16, oneshot::Sender<Vec<Answer>>>>>;

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
pub struct UdpService {
    // serving port, to downstream
    udp: Arc<UdpSocket>,
    // recursive lookup socket, to upstream
    forward: Arc<UdpSocket>,
}

impl UdpService {
    pub fn new(udp: UdpSocket, forward: UdpSocket) -> UdpService {
        UdpService {
            udp: Arc::new(udp),
            forward: Arc::new(forward),
        }
    }

    pub async fn run_forward(
        self: Arc<Self>,
        mut recur_receiver: mpsc::UnboundedReceiver<Task>,
    ) -> Result<(), std::io::Error> {
        let mp: TaskMap = Arc::new(Mutex::new(BTreeMap::new()));

        let (buf_sender, mut buf_receiver) = mpsc::channel::<Bytes>(4);

        let s = self.clone();
        tracing::debug!("setting up listener");

        // passing answers back to forward lookup
        let listening = tokio::spawn(forward::listening(s.forward.clone(), mp.clone()));

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
            let query = pkt.question.clone().unwrap();

            // spawn a new task to proceed the packet
            let s = s.clone();
            tokio::spawn(async move {
                let id = pkt.get_id();
                let rs = transaction(pkt, task_sender).await;
                if rs.is_err() {
                    s.udp_fail(rs.unwrap_err(), client).await;
                    return;
                }
                let answers = rs.unwrap();
                let mut resp = Packet::new_plain_answer(id);
                for ans in answers {
                    match ans {
                        Answer::Error(rcode) => {
                            resp = Packet::new_failure(id, rcode);
                            break;
                        }
                        Answer::Answer(ans) => resp.add_answer(ans),
                        Answer::NameServer(ns) => resp.add_authority(ns),
                        Answer::Additional(ad) => resp.add_addition(ad),
                    }
                }
                resp.set_question(query);
                let packet = resp.into_bytes();
                let udp = s.udp.clone();
                udp.send_to(&packet, client).await.unwrap();
            });
        }
    }
}

async fn transaction(
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

    let query = pkt.question.unwrap();
    let (a_sender, mut a_recv) = mpsc::unbounded_channel::<Answer>();
    let task = Task::Query(query, a_sender);
    task_sender.send(task).unwrap();

    let mut answers = vec![];
    while let Some(answer) = a_recv.recv().await {
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
