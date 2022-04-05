use bytes::{Buf, BufMut, BytesMut};

use super::{domain::Name, error::PacketError, PacketContent, RRClass, RRType};

pub struct Question {
    name: Name,
    ty: RRType,
    class: RRClass,
    size: usize,
}

impl Question {
    pub fn build(name: Name, ty: RRType, class: RRClass) -> Self {
        let size = name.len() + 1 + 2 * 2;
        Self {
            name,
            ty,
            class,
            size,
        }
    }
    pub fn get_name(&self) -> Name {
        self.name.clone()
    }
    pub fn get_type(&self) -> RRType {
        self.ty
    }
    pub fn get_class(&self) -> RRClass {
        self.class
    }

    pub fn set_name(&mut self, name: Name) {
        self.name = name;
    }

    pub fn set_name_unchecked(&mut self, name: &str) {
        let name = Name::try_from(name).unwrap();
        self.name = name;
    }
}

impl PacketContent for Question {
    fn size(&self) -> usize {
        self.size
    }

    fn parse(packet: bytes::Bytes, pos: usize) -> Result<Self, PacketError>
    where
        Self: Sized,
    {
        let (name, end) = Name::parse(packet.clone(), pos)?;
        let mut p = packet;
        p.advance(end);
        let ty = RRType::from(p.get_u16());
        let class = RRClass::from(p.get_u16());
        let size = end + 4 - pos;
        Ok(Self {
            name,
            ty,
            class,
            size,
        })
    }

    fn into_bytes(self) -> Result<BytesMut, PacketError> {
        let mut buf = BytesMut::with_capacity(self.name.len() + 5);
        buf.put(self.name.as_bytes_uncompressed());
        buf.put_u16(u16::from(self.ty));
        buf.put_u16(u16::from(self.class));
        Ok(buf)
    }
}

#[test]
fn test_build() {
    let name = Name::try_from("example.com").unwrap();
    let ty = RRType::from(1);
    let class = RRClass::from(1);
    let question = Question::build(name.clone(), ty, class);
    assert_eq!(question.get_name(), name);
    assert_eq!(question.get_type(), ty);
    assert_eq!(question.get_class(), class);
}

#[test]
fn test_parse() {
    let bytes = bytes::Bytes::from(vec![
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // domain name
        0, 1, // type
        0, 1, // class
    ]);

    let size = bytes.len();

    let parsed = Question::parse(bytes, 0);
    assert!(parsed.is_ok());
    let ques = parsed.unwrap();
    let name = ques.get_name();
    let ty = ques.get_type();
    let class = ques.get_class();

    let n = name.to_string();
    assert_eq!(n, "example.com.");
    assert_eq!(ty, RRType::A);
    assert_eq!(class, RRClass::Internet);
    assert_eq!(size, ques.size());
}
