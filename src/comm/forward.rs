use std::sync::Arc;

use bytes::BytesMut;
use tokio::net::{TcpStream, UdpSocket};
use tracing;

use crate::comm::{Answer, TaskMap};
use crate::protocol::{Packet, TransactionError};

pub async fn listening(forward: Arc<UdpSocket>, map: TaskMap) {
    let mut buf = BytesMut::from(&[0_u8; 1024][..]);
    while let Ok(sz) = forward.recv(&mut buf).await {
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
                let rrs = pkt
                    .answers
                    .into_iter()
                    .map(Answer::Answer)
                    .chain(pkt.authorities.into_iter().map(Answer::NameServer))
                    .chain(pkt.additions.into_iter().map(Answer::Additional))
                    .collect();
                {
                    let mut guard = map.lock().await;
                    if let Some(sender) = guard.remove(&id) {
                        sender.send(rrs).unwrap();
                    }
                }
            }
            Err(TransactionError {
                    id: Some(id),
                    error,
                }) => {
                let err = vec![Answer::Error(error)];
                {
                    let mut guard = map.lock().await;
                    if let Some(sender) = guard.remove(&id) {
                        sender.send(err).unwrap();
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
}
