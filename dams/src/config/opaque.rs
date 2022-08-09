use argon2::Argon2;
use opaque_ke::{key_exchange::tripledh::TripleDh, CipherSuite, Ristretto255};

#[allow(dead_code)]
#[derive(Debug)]
pub struct OpaqueCipherSuite;

impl CipherSuite for OpaqueCipherSuite {
    type OprfCs = Ristretto255;
    type KeGroup = Ristretto255;
    type KeyExchange = TripleDh;
    type Ksf = Argon2<'static>;
}
