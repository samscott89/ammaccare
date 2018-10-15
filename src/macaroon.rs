// External imports
use url::Url;

// Std imports
use std::borrow::Cow;
use std::fmt::Debug;

// Local imports
use super::{crypto, caveat, AsBytes};
use crypto::Signature;
use super::caveat::Caveat;

#[derive(Clone, Debug)]
enum Version {
    V1,
    V2,
}


pub struct Macaroon {
    location: Vec<u8>,
    identifier: Vec<u8>,
    signature: crypto::Signature,
    caveats: Vec<Caveat>
}


fn parse_location(location: &[u8]) -> Location {
    unimplemented!()
}

fn parse_identifier(id: &[u8]) -> Identifier {
    unimplemented!()
}

impl Macaroon {
    pub fn new(key: &[u8], identifier: Vec<u8>, location: Vec<u8>) -> Self {
        let key = crypto::macaroon_key(key);
        Self {
            location: location,
            signature: crypto::mac(&key, &identifier).into(),
            identifier: identifier,
            caveats: Vec::new(),
        }
    }

    fn add_caveat(&mut self, caveat: Caveat) {
        let sig = crypto::mac2(&self.signature, &caveat.vid(), &caveat.cid());
        self.caveats.push(caveat);
        self.signature = sig;
    }

    pub fn add_third_party_caveat(&mut self, mut caveat: Caveat, caveat_key: Vec<u8>) {
        let vid = crypto::senc(&self.signature, &caveat_key);
        caveat.set_vid(vid);
        caveat.set_key(caveat_key);
        self.add_caveat(caveat);
    }

    pub fn add_first_party_caveat(&mut self, caveat: Caveat) {
        self.add_caveat(caveat);
    }

    pub fn bind_for_request(&self, signature: &Signature) -> Signature {
        crypto::mac(signature, &self.signature.as_bytes())
    }

    pub fn prepare(&self, discharge: &mut Macaroon) {
        discharge.signature = self.bind_for_request(&discharge.signature);
    }

    pub fn verify_caveats(&self, sig: &mut Signature, target: &Macaroon, discharges: &[Macaroon]) -> bool {
        for caveat in self.caveats.iter() {
            if caveat.is_third_party() {
                // println!("Check third party predicate: {:#?}", &caveat);
                let caveat_key = match crypto::sdec(&*sig, &caveat.vid()) {
                    Ok(ck) => ck,
                    Err(_) => return false,
                };
                let mut checked = false;
                for discharge in discharges {
                    if &discharge.identifier == &caveat.cid().as_ref() &&
                        discharge.verify_inner(&caveat_key, &self, discharges) {
                        // println!("Verified with {:#?}", discharge);
                        checked = true;
                    }
                }
                if !checked {
                    println!("Failed to check caveat");
                    return false;
                }
            } else {
                if !caveat.validate() {
                    return false
                }
                // println!("Check first party predicate: {:#?}", &caveat);            
            }
            // *sig = format!("MAC({}, {} :: {})", sig, &caveat.vid.clone().unwrap_or("".to_string()), &caveat.cid);
            *sig = crypto::mac2(&*sig, &caveat.vid(), &caveat.cid())
        }
        true
    }

    pub fn verify(&self, key: &[u8], discharges: &[Macaroon]) -> bool {
        let key = crypto::macaroon_key(key);
        let mut sig: Signature = crypto::mac(&key, &self.identifier).into();
        let checked = self.verify_caveats(&mut sig, &self, discharges);
        checked && sig == self.signature
    }

    fn verify_inner(&self, key: &[u8], target: &Macaroon, discharges: &[Macaroon]) -> bool {
        let key = crypto::macaroon_key(key);
        let mut sig: Signature = crypto::mac(&key, &self.identifier).into();
        let checked = self.verify_caveats(&mut sig, target, discharges);
        sig = target.bind_for_request(&sig);
        checked && sig == self.signature
    }
}

#[derive(Clone, Debug)]
pub struct Location {
    url: Url,
}

#[derive(Clone, Debug)]
pub struct Identifier {
    query_type: String,
    app_id: String,
    secret_name: String,
}

impl AsBytes for Identifier {
    fn as_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        let mut res = Vec::new();
        res.extend_from_slice(self.query_type.as_bytes());
        res.extend_from_slice(b" :: ");
        res.extend_from_slice(self.app_id.as_bytes());
        res.extend_from_slice(b" :: ");
        res.extend_from_slice(self.secret_name.as_bytes());
        Cow::from(res)
    }
}


impl AsBytes for Location {
    fn as_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        Cow::from(self.url.to_string().into_bytes())
    }
}



#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn plain_macaroon() {
        let key = b"Kee.sh service macaroon root key";

        let macaroon = Macaroon::new(
            key,
            b"test id".to_vec(),
            b"https://kee.sh".to_vec()
        );

        assert!(macaroon.verify(key, &[]));
    }

    #[test]
    fn with_caveat() {
        let key = b"Kee.sh service macaroon root key";

        let mut macaroon = Macaroon::new(
            key,
            b"test id".to_vec(),
            b"https://kee.sh".to_vec()
        );

        let caveat = Caveat::new(b"this is a test".to_vec(), b"TEST//https://kee.sh".to_vec());
        macaroon.add_first_party_caveat(caveat);

        assert!(macaroon.verify(key, &[]));
    }

    #[test]
    fn with_wrong_caveat() {
        let key = b"Kee.sh service macaroon root key";

        let mut macaroon = Macaroon::new(
            key,
            b"test id".to_vec(),
            b"https://kee.sh".to_vec()
        );

        let caveat = Caveat::new(b"this is a test".to_vec(), b"https://kee.sh".to_vec());
        macaroon.add_first_party_caveat(caveat);

        assert!(!macaroon.verify(key, &[]));
    }

    use caveat::ThirdParty;

    #[test]
    fn with_third_party_caveat() {
        let key = b"Kee.sh service macaroon root key";

        let third_party = caveat::LookupCid::new();

        let mut macaroon = Macaroon::new(
            key,
            b"test id".to_vec(),
            b"https://kee.sh".to_vec()
        );


        let ck = b"Some new freshly generated key..".to_vec();
        let cid = third_party.get_cid(ck.clone(), b"Validation test for the third party".to_vec());

        let tp_loc = b"TEST//https://other.kee.sh".to_vec();
        let caveat = Caveat::new(cid.clone(), tp_loc.clone());
        macaroon.add_third_party_caveat(caveat, ck);

        // will not verify without discharge
        assert!(!macaroon.verify(key, &[]));


        // "send" the cid to the other party
        let (ck, preds) = third_party.from_cid(cid.clone()).unwrap();
        // receive discharge
        let mut discharge = Macaroon::new(&ck, cid, tp_loc);

        // bind to macaroon
        macaroon.prepare(&mut discharge);

        assert!(macaroon.verify(key, &[discharge]));
    }
}