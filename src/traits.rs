use std::convert::TryInto;
use std::mem::size_of;

pub trait FromBytes {
    fn from_bytes(bytes: &[u8]) -> Option<Self>
    where
        Self: Sized;
}

pub trait ToBytes {
    fn to_bytes(self) -> Vec<u8>;
}

macro_rules! impl_from_to_bytes {
    ($t:ty) => {
        impl FromBytes for $t {
            fn from_bytes(bytes: &[u8]) -> Option<Self> {
                let n: [u8; size_of::<$t>()] = bytes.try_into().ok()?;
                Some(<$t>::from_ne_bytes(n))
            }
        }

        impl ToBytes for $t {
            fn to_bytes(self) -> Vec<u8> {
                self.to_ne_bytes().to_vec()
            }
        }
    };
}

impl_from_to_bytes!(u8);
impl_from_to_bytes!(u16);
impl_from_to_bytes!(u32);
impl_from_to_bytes!(u64);
impl_from_to_bytes!(u128);
impl_from_to_bytes!(usize);

impl_from_to_bytes!(i8);
impl_from_to_bytes!(i16);
impl_from_to_bytes!(i32);
impl_from_to_bytes!(i64);
impl_from_to_bytes!(i128);
impl_from_to_bytes!(isize);

impl_from_to_bytes!(f32);
impl_from_to_bytes!(f64);
