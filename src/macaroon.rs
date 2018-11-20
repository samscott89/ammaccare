// External imports
use data_encoding::BASE64_NOPAD;

// Std imports
use std::fmt;
use std::str;

// Local imports
use super::crypto;
use crypto::Signature;
use super::caveat::Caveat;

#[derive(Clone, Deserialize, Serialize)]
pub struct Macaroon {
    // location: Vec<u8>,
    identifier: Vec<u8>,
    signature: crypto::Signature,
    caveats: Vec<Caveat>,
    discharges: Vec<Macaroon>,
}

impl fmt::Debug for Macaroon {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        let id = str::from_utf8(&self.identifier);
        let id = match id {
            Ok(ref s) if s.is_ascii() => format!("Decoded: {}", s),
            _ => format!("Opaque: {}", BASE64_NOPAD.encode(&self.identifier)),
        };
        f.debug_struct("Macaroon")
         .field("id", &id)
         .field("caveats", &self.caveats)
         .field("discharges", &self.discharges)
         .finish()
    }
}

impl Macaroon {
    pub fn new(key: &[u8], identifier: Vec<u8>) -> Self {
        let key = crypto::macaroon_key(key);
        Self {
            signature: crypto::mac(&key, &identifier),
            identifier,
            caveats: Vec::new(),
            discharges: Vec::new(),
        }
    }

    pub fn caveats(&self) -> &[Caveat] {
        &self.caveats
    }

    fn add_caveat(&mut self, caveat: Caveat) {
        let sig = crypto::mac2(&self.signature, &caveat.vid(), &caveat.cid());
        self.caveats.push(caveat);
        self.signature = sig;
    }

    pub fn add_third_party_caveat(&mut self, mut caveat: Caveat, caveat_key: &[u8]) {
        let vid = crypto::senc(&self.signature, &caveat_key);
        caveat.set_vid(vid);
        self.add_caveat(caveat);
    }

    pub fn add_first_party_caveat(&mut self, caveat: Caveat) {
        self.add_caveat(caveat);
    }

    pub fn bind_for_request(&self, signature: &Signature) -> Signature {
        crypto::mac(signature, &self.signature.as_slice())
    }

    pub fn prepare(&mut self, mut discharge: Macaroon) {
        discharge.signature = self.bind_for_request(&discharge.signature);
        self.discharges.push(discharge);
    }

    pub fn verify_caveats(&self, sig: &mut Signature) -> bool {
        for caveat in self.caveats.iter() {
            if caveat.is_third_party() {
                // println!("Check third party predicate: {:#?}", &caveat);
                let caveat_key = match crypto::sdec(&*sig, &caveat.vid()) {
                    Ok(ck) => ck,
                    Err(_) => return false,
                };
                let mut checked = false;
                for discharge in self.discharges.iter() {
                    if discharge.identifier == caveat.cid().as_ref() &&
                        discharge.verify_inner(&caveat_key, &self) {
                        // println!("Verified with {:#?}", discharge);
                        checked = true;
                    }
                }
                if !checked {
                    println!("Failed to check caveat");
                    return false;
                }
            } else if !caveat.validate() {
                return false
            }
            // *sig = format!("MAC({}, {} :: {})", sig, &caveat.vid.clone().unwrap_or("".to_string()), &caveat.cid);
            *sig = crypto::mac2(&*sig, &caveat.vid(), &caveat.cid())
        }
        true
    }

    pub fn verify(&self, key: &[u8]) -> bool {
        let key = crypto::macaroon_key(key);
        let mut sig: Signature = crypto::mac(&key, &self.identifier);
        let checked = self.verify_caveats(&mut sig);
        checked && sig == self.signature
    }

    fn verify_inner(&self, key: &[u8], target: &Macaroon) -> bool {
        let key = crypto::macaroon_key(key);
        let mut sig: Signature = crypto::mac(&key, &self.identifier);
        let checked = self.verify_caveats(&mut sig);
        sig = target.bind_for_request(&sig);
        checked && sig == self.signature
    }
}


#[derive(Clone, Debug)]
pub struct Identifier {
    query_type: String,
    app_id: String,
    secret_name: String,
}

#[cfg(test)]
mod test {
    use super::*;
    use caveat;
    use caveat::ThirdParty;

    #[test]
    fn plain_macaroon() {
        let key = b"Kee.sh service macaroon root key";

        let macaroon = Macaroon::new(
            key,
            b"test id".to_vec(),
        );

        assert!(macaroon.verify(key));
    }

    #[test]
    fn with_caveat() {
        let key = b"Kee.sh service macaroon root key";

        let mut macaroon = Macaroon::new(
            key,
            b"test id".to_vec(),
        );

        let caveat = Caveat::new(b"TEST//this is a test".to_vec());
        macaroon.add_first_party_caveat(caveat);

        assert!(macaroon.verify(key));
    }

    #[test]
    fn with_wrong_caveat() {
        let key = b"Kee.sh service macaroon root key";

        let mut macaroon = Macaroon::new(
            key,
            b"test id".to_vec(),
        );

        let caveat = Caveat::new(b"broken test".to_vec());
        macaroon.add_first_party_caveat(caveat);

        assert!(!macaroon.verify(key));
    }

    #[test]
    fn with_third_party_caveat() {
        let key = b"Kee.sh service macaroon root key";

        let third_party = caveat::LookupCid::new();

        let mut macaroon = Macaroon::new(
            key,
            b"test id".to_vec(),
        );


        let ck = b"Some new freshly generated key..".to_vec();
        let cid = third_party.get_cid(ck.clone(), b"Validation test for the third party".to_vec());

        let caveat = Caveat::new(cid.clone());
        macaroon.add_third_party_caveat(caveat, &ck);

        // will not verify without discharge
        assert!(!macaroon.verify(key));


        // "send" the cid to the other party
        let (ck, _preds) = third_party.from_cid(&cid).unwrap();
        // receive discharge
        let discharge = Macaroon::new(&ck, cid);

        // bind to macaroon
        macaroon.prepare(discharge);

        assert!(macaroon.verify(key));
        println!("{:#?}", macaroon);
    }
}