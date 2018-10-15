// External imports
use failure::Error;
use sodiumoxide::randombytes;

// Std imports
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::Sized;
use std::str;

// Project imports
use super::macaroon::Macaroon;

/// A simple container for the caveat values.
/// By itself just holds bytes, but can be used with a `Validator`
/// implementation to 
#[derive(Clone, Debug)]
pub struct Caveat {
    pub cid: Vec<u8>,
    pub vid: Option<Vec<u8>>,
    pub cl: Vec<u8>,
    pub key: Option<Vec<u8>>,
}

impl Caveat {
    pub fn new(predicate: Vec<u8>, location: Vec<u8>) -> Self {
        Self {
            cid: predicate,
            vid: None,
            cl: location,
            key: None,
        }
    }

    pub fn is_third_party(&self) -> bool {
        !self.vid.is_none()
    }

    pub fn validate(&self) -> bool {
        if let Some(val) = self.get_validator() {
            val.validate(self)
        } else {
            false
        }
    }

    pub fn get_validator(&self) -> Option<Box<Validator>> {
        let loc = str::from_utf8(&self.cl).ok()?;
        match loc {
            #[cfg(test)]
            x if x.starts_with("TEST//") => Some(Box::new(TestValidator)),
            _ => None
        }
    }



    pub fn cid<'a>(&'a self) -> Cow<'a, [u8]> {
        Cow::from(&self.cid)
    }
    pub fn vid<'a>(&'a self) -> Cow<'a, [u8]> {
        self.vid.as_ref().map(|vid| Cow::from(vid)).unwrap_or(Cow::from(vec![]))
    }
    pub fn loc<'a>(&'a self) -> Cow<'a, [u8]> {
        Cow::from(&self.cl)
    }
    pub fn key<'a>(&'a self) -> Cow<'a, [u8]> {
        self.key.as_ref().map(|key| Cow::from(key)).unwrap_or(Cow::from(vec![]))
    }


    pub fn set_vid(&mut self, vid: Vec<u8>) {
        self.vid = Some(vid)
    }
    pub fn set_key(&mut self, key: Vec<u8>) {
        self.key = Some(key)
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

#[inline]
fn opt_to_string<'a>(opt: Option<&'a [u8]>) -> Option<String> {
    opt.and_then(|vid: &[u8]| String::from_utf8(vid.to_vec()).ok())
}

pub trait ThirdParty {
    fn get_cid(&self, key: Vec<u8>, identifier: Vec<u8>) -> Vec<u8>;

    fn from_cid(&self, cid: Vec<u8>) -> Option<(Vec<u8>, Vec<u8>)>;
}

pub struct LookupCid {
    table: RefCell<HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>>,
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

    fn from_cid(&self, cid: Vec<u8>) -> Option<(Vec<u8>, Vec<u8>)> {
        self.table.borrow().get(&cid).map(|c| c.clone())
    }

}