use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use rand::prelude::random;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio::{net::UdpSocket, sync::OnceCell};

use crate::protocol::{Packet, PacketError, Question, RR};

static TIME_OUT: OnceCell<Duration> = OnceCell::const_new();

async fn get_time_out() -> Duration {
    *TIME_OUT
        .get_or_init(|| async { Duration::from_secs(5) })
        .await
}

#[derive(Debug)]
pub enum Task {
    Query(Question, mpsc::Sender<Answer>),
}

#[derive(Debug)]
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
        &'static self,
        mut recur_receiver: mpsc::Receiver<Task>,
    ) -> Result<(), std::io::Error> {
        let mp: Arc<Mutex<BTreeMap<u16, mpsc::Sender<Vec<Answer>>>>> =
            Arc::new(Mutex::new(BTreeMap::new()));

        let mp_listener = mp.clone();
        let (buf_sender, mut buf_receiver) = mpsc::channel::<Bytes>(4);

        let listening = tokio::spawn(async move {
            // this handle will receive packet from upstream and push them into map
            let mut buf = BytesMut::new();
            while let Ok(sz) = self.forward.clone().recv(&mut buf).await {
                if sz < 20 {
                    // malformed packet
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
                        let sender;
                        {
                            let guard = mp.lock().await;
                            sender = guard.get(&id);
                            if sender.is_none() {
                                return;
                            }
                            let sender = sender.unwrap();
                            sender.send(answers).await.unwrap();
                        }
                    }
                    Err(_e) => {
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
            let (checker_sender, mut checker_receiver) = mpsc::channel(1);
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
                let answers = timeout(get_time_out().await, checker_receiver.recv()).await;
                if answers.is_err() {
                    // timeout
                    answer_sender
                        .send(Answer::Error(PacketError::ServFail))
                        .await
                        .unwrap();
                    return;
                }
                let answers = answers.unwrap();
                if answers.is_none() {
                    // sender closed unexpectedly
                    answer_sender
                        .send(Answer::Error(PacketError::ServFail))
                        .await
                        .unwrap();
                    return;
                }
                let answers = answers.unwrap();
                for answer in answers.into_iter() {
                    answer_sender.send(answer).await.unwrap();
                }
            });
            checkers.push(checker);
        }
        tokio::join!(listening, forwarding);
        futures::future::join_all(checkers);
        Ok(())
    }

    async fn transaction(
        &self,
        pkt: Packet,
        task_sender: mpsc::Sender<Task>,
    ) -> Result<Vec<Answer>, PacketError> {
        if !pkt.is_query() {
            return Err(PacketError::ServFail);
        }

        let mut rxs = vec![];
        for query in pkt.questions {
            let (a_sender, a_recv) = mpsc::channel::<Answer>(1);
            let task = Task::Query(query, a_sender);
            rxs.push(a_recv);
            task_sender.send(task).await.unwrap();
        }
        let mut answers = vec![];
        for rx in rxs.iter_mut() {
            let answer = rx.recv().await.unwrap();
            match answer {
                Answer::Error(err) => return Err(err),
                answer => answers.push(answer),
            }
        }

        Ok(answers)
    }

    async fn udp_fail(&self, id: u16, err: PacketError, client: SocketAddr) {
        let udp = self.udp.clone();
        let packet = Packet::new_failure(id, err);
        udp.send_to(&packet.into_bytes(), client).await.unwrap();
    }

    pub async fn run_udp(
        &'static self,
        task_sender: mpsc::Sender<Task>,
    ) -> Result<(), std::io::Error> {
        loop {
            // receive packet
            let mut packet = BytesMut::new();
            let (n, client) = self.udp.recv_from(&mut packet).await?;

            // validate packet
            if n < 12 {
                // ignore
                continue;
            }
            let pkt = match Packet::parse_packet(packet.clone().into(), 0) {
                Ok(pkt) => pkt,
                Err(err) => {
                    tokio::spawn(async move {
                        let id = ((packet[0] as u16) << 8) | (packet[1] as u16);
                        self.udp_fail(id, err, client).await;
                    });
                    continue;
                }
            };

            let task_sender = task_sender.clone();

            // spawn a new task to proceed the packet
            tokio::spawn(async move {
                let id = pkt.get_id();
                let rs = self.transaction(pkt, task_sender).await;
                if rs.is_err() {
                    self.udp_fail(id, rs.unwrap_err(), client).await;
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
                let udp = self.udp.clone();
                udp.send_to(&packet, client).await.unwrap();
            });
        }
    }
}
