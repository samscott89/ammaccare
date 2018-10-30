// External imports
use sodiumoxide::crypto::auth::hmacsha256 as hmac;
use sodiumoxide::crypto::secretbox;

// Std imports
use std::borrow::Cow;
use std::mem;

// Local imports
// ...


pub fn mac<'a, K: Into<&'a hmac::Key>>(key: K, x: &[u8]) -> Signature {
    hmac::authenticate(x, key.into()).into()
}

pub fn mac2<'a, K: Into<&'a hmac::Key>>(key: K, x1: &[u8], x2: &[u8]) -> Signature {
    let mut state = hmac::State::init(&key.into().0);
    state.update(x1);
    state.update(x2);
    state.finalize().into()
}

pub fn senc<'a, K: Into<&'a secretbox::Key>>(key: K, m: &[u8]) -> Vec<u8> {
    let nonce = secretbox::gen_nonce();
    let ct = secretbox::seal(m, &nonce, key.into());
    let mut output = nonce.0.to_vec();
    output.extend_from_slice(&ct);
    output
}

pub fn sdec<'a, K: Into<&'a secretbox::Key>>(key: K, ct: &[u8]) -> Result<Vec<u8>, ()> {
    let nonce = secretbox::Nonce::from_slice(&ct[..secretbox::NONCEBYTES]).unwrap();
    secretbox::open(&ct[secretbox::NONCEBYTES..], &nonce, key.into())
}

// Macaroons personalize the HMAC key using the string
// "macaroons-key-generator" padded to 32-bytes with zeroes
pub const KEY_GENERATOR: &'static [u8; 32] = b"macaroons-key-generator\0\0\0\0\0\0\0\0\0";

pub fn macaroon_key(key: &[u8]) -> Signature {
    hmac::authenticate(&key, &hmac::Key(*KEY_GENERATOR)).into()
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Signature([u8; hmac::TAGBYTES]);

impl Signature {
    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
}

impl<'a> Into<&'a secretbox::Key> for &'a Signature {
    fn into(self) -> &'a secretbox::Key {
        unsafe {
            mem::transmute(self)
        }
    } 
}

impl<'a> Into<&'a hmac::Key> for &'a Signature {
    fn into(self) -> &'a hmac::Key {
        unsafe {
            mem::transmute(self)
        }
    } 
}

impl<'a> Into<&'a hmac::Key> for &'a mut Signature {
    fn into(self) -> &'a hmac::Key {
        unsafe {
            mem::transmute(self)
        }
    } 
}

impl From<hmac::Tag> for Signature {
    fn from(other: hmac::Tag) -> Self {
        Signature(other.0)
    }
}
