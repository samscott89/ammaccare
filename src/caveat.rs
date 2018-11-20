// External imports
use data_encoding::BASE64_NOPAD;
use sodiumoxide::{crypto::auth::hmacsha256 as hmac, randombytes};

// Std imports
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::str;

// Project imports
use super::crypto;

/// A simple container for the caveat values.
/// By itself just holds bytes, but can be used with a `Validator`
/// implementation to 
#[derive(Clone, Deserialize, Serialize)]
pub struct Caveat {
    pub cid: Vec<u8>,
    pub vid: Option<Vec<u8>>,
    pub cl: Option<Vec<u8>>,
}

impl fmt::Debug for Caveat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let cl = self.cl.as_ref().map(|cl| {
            match str::from_utf8(&cl){
                Ok(ref s) if s.is_ascii() => format!("Decoded: {}", s),
                _ => format!("Opaque: {}", BASE64_NOPAD.encode(&cl)),
            }
        });
        let cid = BASE64_NOPAD.encode(&self.cid);
        let vid = self.vid.as_ref().map(|vid| BASE64_NOPAD.encode(&vid));

        f.debug_struct("Caveat")
         .field("cid", &cid)
         .field("vid", &vid)
         .field("cl", &cl)
         .finish()
    }
}


impl Caveat {
    pub fn new(predicate: Vec<u8>) -> Self {
        Self {
            cid: predicate,
            vid: None,
            cl: None,
        }
    }

    pub fn is_third_party(&self) -> bool {
        self.vid.is_some()
    }

    pub fn validate(&self) -> bool {
        if let Some(val) = self.get_validator() {
            val.validate(self)
        } else {
            false
        }
    }

    pub fn get_validator(&self) -> Option<Box<Validator>> {
        let id = str::from_utf8(&self.cid).ok()?;
        match id {
            #[cfg(test)]
            x if x.starts_with("TEST//") => Some(Box::new(TestValidator)),
            _ => None
        }
    }



    pub fn cid(&self) -> Cow<[u8]> {
        Cow::from(&self.cid)
    }

    pub fn vid(&self) -> Cow<[u8]> {
        self.vid.as_ref().map(Cow::from).unwrap_or_else(|| Cow::from(vec![]))
    }

    pub fn set_vid(&mut self, vid: Vec<u8>) {
        self.vid = Some(vid)
    }
}

pub trait Validator {
    fn validate(&self, caveat: &Caveat) -> bool;
}

#[cfg(test)]
pub struct TestValidator;

#[cfg(test)]
impl Validator for TestValidator {
    fn validate(&self, caveat: &Caveat) -> bool {
        println!("Validate: {}", str::from_utf8(&caveat.cid).unwrap());
        true
    }
}

pub trait ThirdParty {
    fn get_cid(&self, key: Vec<u8>, identifier: Vec<u8>) -> Vec<u8>;

    fn from_cid(&self, cid: &[u8]) -> Option<(Vec<u8>, Vec<u8>)>;
}

type CidToKeyId = HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>;

#[derive(Default)]
pub struct LookupCid {
    table: RefCell<CidToKeyId>,
}

impl LookupCid {
    pub fn new() -> Self {
        Self {
            table: RefCell::new(HashMap::new())
        }
    }
}

impl ThirdParty for LookupCid {
    fn get_cid(&self, key: Vec<u8>, identifier: Vec<u8>) -> Vec<u8> {
        let cid = randombytes::randombytes(32);
        self.table.borrow_mut().insert(cid.clone(), (key, identifier));
        cid
    }

    fn from_cid(&self, cid: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        self.table.borrow().get(cid).cloned()
    }
}

pub struct EncryptedChallenge {
    shared_key: crypto::Signature,
}

impl EncryptedChallenge {
    pub fn new(key: &[u8]) -> Self {
        EncryptedChallenge {
            shared_key: hmac::authenticate(key, &hmac::Key(*b"ammaccare-encryptedchallenge-key")).into()
        }
    }

    pub fn fresh(&self) -> (Caveat, Vec<u8>) {
        let key = randombytes::randombytes(32); 
        let id  = randombytes::randombytes(32);
        let cid = self.get_cid(key.clone(), id);
        (Caveat::new(cid), key)
    }
}

impl ThirdParty for EncryptedChallenge {
    fn get_cid(&self, key: Vec<u8>, identifier: Vec<u8>) -> Vec<u8> {
        // todo: make this serialized using bincode or something
        let mut pt = key.clone();
        pt.extend_from_slice(&identifier[..]);
        crypto::senc(&self.shared_key, &pt[..])
    }

    fn from_cid(&self, cid: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let pt = crypto::sdec(&self.shared_key, cid);
        if let Ok(mut pt) = pt {
            // TODO: remove hardcoded length
            let identifier = pt.split_off(32);
            Some((pt, identifier))
        } else {
            None
        }
    }
}
