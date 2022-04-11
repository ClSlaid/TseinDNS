use std::fmt::{Debug, Display, Write};

use bytes::{BufMut, Bytes, BytesMut};
use color_eyre::{eyre::eyre, Result};

use crate::protocol::error::PacketError;

const MAX_LABEL_LENGTH: usize = 63;
const MAX_NAME_LENGTH: usize = 253;

pub const PTR_MASK: u8 = 0xc0;

// TODO: replace `Label` with bytes::Bytes to reduce memory usage.
type Label = String;

/// ## `Name` represents domain name.
/// `Name` stores domain name as a vector of `Label`s. For example, `www.google.com.cn` could be represented as following pseudo code:
/// ```text
/// Name {vec![Label("www"), Label("google"), Label("com"), Label("cn")]}
/// ```
#[derive(Clone)]
pub struct Name {
    labels: Vec<Label>,
}

impl Name {
    pub fn try_from(s: &str) -> Result<Self> {
        let mut labels = vec![];
        let mut total_len = 0;
        for l in s.split('.').filter(|p| !p.is_empty()) {
            let len = l.len();
            if len > MAX_LABEL_LENGTH {
                return Err(eyre!("Label too long"));
            }
            let label = Label::from(l);
            labels.push(label);
            total_len += len + 1;
        }
        if total_len > MAX_NAME_LENGTH {
            Err(eyre!("Label too long"))
        } else {
            Ok(Self { labels })
        }
    }

    /// length of domain name string
    ///
    /// For example, `"example.com.".len()` is 12
    pub fn len(&self) -> usize {
        if self.labels.is_empty() {
            1
        } else {
            self.labels.len() + self.labels.iter().fold(0, |acc, label| acc + label.len())
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// parse `domain` from raw packet bytes
    ///
    /// If ok, return the Domain name and the end position of domain name in packet.
    ///
    /// If err, return `PacketError::FormatError`
    pub fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError>
    where
        Self: Sized,
    {
        let mut pos = pos;
        const MAX_JUMPS: usize = 5;
        let mut jumps = 0;

        let mut is_jumped = false;
        let mut domain_end = 0; // end of domain name data in packet

        let mut labels = vec![];
        let mut size = 0;

        // empty domain
        if packet[pos] == 0 {
            return Ok((Self { labels: vec![] }, pos + 1));
        }

        loop {
            if jumps > MAX_JUMPS || pos >= packet.len() {
                return Err(PacketError::FormatError);
            }

            match packet[pos] {
                0 => break,

                jmp if jmp & PTR_MASK == PTR_MASK => {
                    if !is_jumped {
                        domain_end = pos + 2;
                    }
                    is_jumped = true;

                    if pos + 1 >= packet.len() {
                        return Err(PacketError::FormatError);
                    }

                    let jmp_high = (jmp ^ PTR_MASK) as usize;
                    let jmp_low = packet[pos + 1] as usize;
                    let jmp_to = (jmp_high << 8) + jmp_low;

                    if jmp_to >= packet.len() {
                        return Err(PacketError::FormatError);
                    }

                    pos = jmp_to;
                    jumps += 1;
                }

                len => {
                    let len = len as usize;
                    let begin = pos + 1;
                    let end = begin + len; // label: slc[begin, end)

                    if end > packet.len() {
                        return Err(PacketError::FormatError);
                    }

                    let label = match Label::from_utf8(packet[begin..end].to_vec()) {
                        Ok(l) => l,
                        Err(_) => return Err(PacketError::FormatError),
                    };

                    labels.push(label);
                    size += len + 1;

                    pos = end;
                    if !is_jumped {
                        domain_end = pos + 1;
                    }
                }
            }
        }
        if size >= MAX_NAME_LENGTH {
            Err(PacketError::FormatError)
        } else {
            Ok((Self { labels }, domain_end))
        }
    }

    pub fn as_bytes_uncompressed(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.len() + 1);
        for label in self.labels.iter() {
            buf.put_u8(label.len() as u8);
            for byte in label.as_bytes().iter() {
                buf.put_u8(*byte);
            }
        }
        buf.put_u8(0);
        buf
    }

    // TODO: implement fn as_bytes_compressed, require a `CompressWriter` struct.

    pub fn is_subdomain_of(&self, other: &Self) -> bool {
        other
            .labels
            .iter()
            .rev()
            .zip(self.labels.iter().rev())
            .all(|(o, s)| *o == *s)
    }
}

impl Debug for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Name")
            .field("labels", &self.labels)
            .field("len", &self.len())
            .finish()
    }
}

// we trust that every label in `Name` is valid
impl Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.labels.is_empty() {
            f.write_char('.')?;
        }
        for label in self.labels.iter() {
            f.write_fmt(format_args!("{}.", label))?;
        }
        Ok(())
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.labels
            .iter()
            .zip(other.labels.iter())
            .all(|(s, o)| *s == *o)
    }
}

#[cfg(test)]
mod domain_test {
    use super::Name;
    use bytes::{Buf, BufMut, Bytes, BytesMut};
    #[test]
    fn test_len() {
        let d1 = Name::try_from("example.com").unwrap();
        let d2 = Name::try_from("example.com.").unwrap();
        assert_eq!(d1.len(), 12);
        assert_eq!(d1.len(), d2.len());
    }

    #[test]
    fn test_subdomain() {
        let domain = Name::try_from("example.com").unwrap();
        let subdomain = Name::try_from("example.example.com").unwrap();
        assert!(subdomain.is_subdomain_of(&domain));
    }

    #[test]
    fn test_try_from() {
        let rs = Name::try_from("example.com");
        assert!(rs.is_ok());
        let n = rs.unwrap();
        assert_eq!(n.to_string(), "example.com.".to_string());

        let rs = Name::try_from(".");
        assert!(rs.is_ok());
        let n = rs.unwrap();
        assert_eq!(n.len(), 1);
    }

    use super::PTR_MASK;
    #[test]
    fn test_parse() {
        fn gen_simple_domain_name(domain: &str) -> Bytes {
            let mut buf = vec![];

            domain
                .split('.')
                .filter(|p| !p.is_empty())
                .for_each(|label| {
                    let len = label.len() as u8;
                    buf.push(len);
                    buf.append(&mut label.as_bytes().to_vec());
                });

            buf.push(0);
            Bytes::from(buf)
        }

        // test empty domain
        let empty = Bytes::from(b"\0".to_vec());
        let parsed = Name::parse(empty, 0);
        assert!(parsed.is_ok());
        let (d, p) = parsed.unwrap();
        assert_eq!(d.to_string(), ".");
        assert_eq!(p, 1);

        // test invalid domain
        let invalid = Bytes::from(b"\x03com\x03".to_vec());
        let parsed = Name::parse(invalid, 0);
        assert!(parsed.is_err());
        let invalid = Bytes::from(b"\x03com".to_vec());
        let parsed = Name::parse(invalid, 0);
        assert!(parsed.is_err());

        // test simple domain
        let packet = gen_simple_domain_name("example.com");
        let (pd, pos) = Name::parse(packet.clone(), 0).unwrap();
        let domain_str = pd.to_string();
        assert_eq!(domain_str, String::from("example.com."));

        // test continually read and compressing
        let mut packet = BytesMut::from(packet.chunk());
        packet.put_u8(7);
        packet.put(&b"example"[..]);
        packet.put_u8(PTR_MASK);
        packet.put_u8(0);
        let packet = packet.copy_to_bytes(packet.len());
        let (pd, end) = Name::parse(packet.clone(), pos).unwrap();
        assert_eq!(pd.to_string(), String::from("example.example.com."));
        assert_eq!(end, packet.len());
    }

    #[test]
    fn test_as_bytes_uncompressed() {
        // test empty domain
        let name = Name::try_from(".").unwrap();
        let encoded: &[u8] = &[0];
        assert_eq!(name.as_bytes_uncompressed(), encoded);

        // test normal domain
        let name = Name::try_from("sm.ms").unwrap();
        let encoded: &[u8] = &[2, b's', b'm', 2, b'm', b's', 0];
        assert_eq!(name.as_bytes_uncompressed(), encoded);
    }
}
