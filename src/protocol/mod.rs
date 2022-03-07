use bytes::{Bytes, BytesMut};

use self::error::PacketError;
trait PacketContent {
    fn size(&self) -> usize;
    fn parse(packet: Bytes, pos: usize) -> Result<Self, PacketError>
    where
        Self: Sized;
    fn into_bytes(self) -> Result<BytesMut, PacketError>;
}

/// this (toy) macron are used for simplify definition of map-like enumerators.
///
/// using:
/// ```
/// pub_map_enum!{
///     Foo<i32> {
///         Foo => 0,
///         Bar => 1;  // <- this is a ';' not a ','
///         Default    // fallback name
///     }
/// }
/// ```
/// defines:
/// ```
/// pub enum Foo {
///     Foo,
///     Bar,
///     Default(i32),   // unmatched value will fallback into Unknown
/// }
/// ```
/// and will automatically implements `From<i32>` for `Foo` and `From<Foo>` for `i32`.
macro_rules! pub_map_enum {
    ($name:ident <$t:ty> {$($key: ident => $value: expr),*; $fallback:ident}) => {
        #[derive(PartialEq, Eq, Debug, Copy, Clone)]
        pub enum $name {
            $($key,)*
            $fallback($t),
        }

        impl From<$t> for $name {
            fn from(value: $t) -> Self {
                match value {
                    $($value => Self::$key,)*
                    value => Self::$fallback(value),
                }
            }
        }

        impl From<$name> for $t {
            fn from(key: $name) -> Self {
                match key {
                    $($name::$key => $value,)*
                    $name::$fallback(value) => value,
                }
            }
        }
    }
}

// Type of Resource Record
pub_map_enum! {RRType<u16> {
    A => 1,
    NS => 2,
    CNAME => 5,
    SOA => 6,
    MX => 15,
    AAAA => 28;
    UNKNOWN
}}

// QClass
pub_map_enum! {RRClass<u16> {
    Reserved => 0,
    Internet => 1,
    Chaos => 3,
    Hesiod => 4;
    Unknown
}}

// testing macron is enough
#[test]
fn test_pub_map_enum() {
    pub_map_enum! {Foo<i32>{
        MyFoo => 0,
        MyBar => 1;
        Unknown
    }}
    let my_foo = Foo::from(0);
    assert_eq!(my_foo, Foo::MyFoo);
    let unknown = Foo::from(114514);
    assert_eq!(unknown, Foo::Unknown(114514));
    assert_eq!(i32::from(my_foo), 0);
    assert_eq!(i32::from(unknown), 114514);
}
/// Domain names
mod domain;
/// Error types
mod error;
/// DNS packet header
mod header;
/// DNS packet question
mod question;
/// DNS Resource Record
mod rr;

#[cfg(test)]
mod integration_tests {}
