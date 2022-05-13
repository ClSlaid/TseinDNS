use tokio::io::AsyncWriteExt;

pub use quic::QuicService;
pub use service::Service;
pub use tcp::TcpService;
pub use tls::{TlsListener, TlsService};

use crate::protocol::{Packet, PacketError, TransactionError};

pub mod quic;
pub mod service;
pub mod tcp;
pub mod tls;
pub(crate) mod worker;

/// use write_packet to write packet into TCP, TLS and IETF-QUIC streams
pub async fn write_packet<S>(stream: &mut S, packet: Packet) -> Result<(), std::io::Error>
where
    S: AsyncWriteExt + Unpin,
{
    let id = packet.get_id();
    let buf = packet.into_bytes();
    if buf.len() > u16::MAX as usize {
        let fail = PacketError::ServFail;
        let resp = Packet::new_failure(id, fail).into_bytes();
        let len = resp.len() as u16;
        stream.write_u16(len).await?;
        return stream.write_all(&resp).await;
    }
    let len = buf.len() as u16;
    stream.write_u16(len).await?;
    stream.write_all(&buf).await
}

pub(crate) async fn stream_fail<S>(
    stream: &mut S,
    err: TransactionError,
) -> Result<(), std::io::Error>
where
    S: AsyncWriteExt + Unpin,
{
    let TransactionError { id, error } = err;
    let id = id.unwrap_or(0);
    let packet = Packet::new_failure(id, error);
    write_packet(stream, packet).await
}
