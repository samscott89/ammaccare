extern crate failure;
extern crate sodiumoxide;
extern crate url;

pub mod caveat;
pub mod crypto;
pub mod macaroon;

use std::borrow::Cow;

pub trait AsBytes {
    fn as_bytes<'a>(&'a self) -> Cow<'a, [u8]>;
}



// pub fn get_secret_token(key: Key, app_id: String, secret_name: String) -> Macaroon {
//     let identifier = format!("{} || {}", app_id, secret_name);
//     // let key = String::from("root_key");
//     let mut macaroon = Macaroon::new(key, identifier);

//     // let ttl_caveat = Caveat::first_party("expires in 1 hour".to_string());
//     // macaroon.add_caveat(ttl_caveat);
//     let authn_key = "K_authn".to_string();
//     let ckn = "ckn".to_string();
//     let cidn = get_third_party_caveat_id(&authn_key, &ckn, format!("app_id = {}", app_id));
//     let authn_caveat = Caveat::third_party(cidn, ckn, (), &macaroon);
//     macaroon.add_caveat(authn_caveat);

//     let authz_key = "K_authz".to_string();
//     let ckz = "ckz".to_string();
//     let cidz = get_third_party_caveat_id(&authz_key, &ckz, format!("app_id = {} has access to secret_name = {}", app_id, secret_name));
//     let authz_caveat = Caveat::third_party(cidz, ckz, (), &macaroon);
//     macaroon.add_caveat(authz_caveat);

//     macaroon
// }

// pub fn encrypt(key: &Key, pt: &String) -> String {
//     format!("Enc({} ,, {})", key, pt)
// }

// pub fn decrypt(key: &Key, ct: &String) -> String {
//     let ct = &ct[4..ct.len() - 1];
//     ct.splitn(2, " ,, ").nth(1).unwrap().to_string()
// }

// type Key = String;
// #[derive(Clone, Debug, Deserialize, Serialize)]
// enum Version {
//     V1,
//     V2,
// }
// type Location = String;
// type Identifier = String;
// type Signature = String;
// type Predicate = String;


// #[derive(Clone, Debug, Deserialize, Serialize)]
// pub struct Macaroon {
//     version: Version,
//     location: Location,
//     identifier: Identifier,
//     signature: Signature,
//     caveats: Vec<Caveat>,
// }

// impl Macaroon {
//     pub fn new(key: Key, identifier: Identifier) -> Self {
//         // let identifier = format!("nonce :: {}", identifier);

//         Self {
//             version: Version::V2,
//             location: (),
//             identifier: identifier.clone(),
//             signature: format!("MAC({}, {})", key, identifier),
//             caveats: Vec::new(),
//         }
//     }

//     pub fn add_caveat(&mut self, caveat: Caveat) {
//         let sig = format!("MAC({}, {} :: {})", self.signature, caveat.vid.clone().unwrap_or("".to_string()), &caveat.cid);
//         self.caveats.push(caveat);
//         self.signature = sig;
//     }

//     pub fn bind_for_request(&self, signature: &Signature) -> Signature {
//         format!("H( {} :: {} )", signature, self.signature)
//     }

//     pub fn prepare(&self, discharge: &mut Macaroon) {
//         discharge.signature = self.bind_for_request(&discharge.signature);
//     }

//     pub fn verify_root(&self, key: Key, app_id: String, secret_name: String, discharges: &[Macaroon]) -> bool {
//         let mut sig = format!("MAC({}, {})", key, self.identifier);
//         println!("Initial sig: {:?}", sig);
//         for caveat in self.caveats.iter() {
//             if let Some(ref vid) = caveat.vid {
//                 println!("Check third party predicate: {:#?}", &caveat);
//                 // let caveat_key = format!("Dec({}, {})", sig, &vid);
//                 let caveat_key = decrypt(&sig, &vid);
//                 println!("Key: {}", caveat_key);
//                 let mut checked = false;
//                 for discharge in discharges {
//                     if discharge.identifier == caveat.cid &&
//                         discharge.verify(caveat_key.clone(), app_id.clone(), secret_name.clone(), &self, discharges) {
//                         println!("Verified with {:#?}", discharge);
//                         checked = true;
//                     }
//                 }
//                 if !checked {
//                     println!("Failed to check caveat");
//                     return false;
//                 }
//             } else {
//                 println!("Check first party predicate: {:#?}", &caveat);            
//             }
//             sig = format!("MAC({}, {} :: {})", sig, &caveat.vid.clone().unwrap_or("".to_string()), &caveat.cid);
//             println!("Updated sig: {}", sig);

//         }

//         // sig = target.bind_for_request(&sig);
//         println!("Final sig: {}\nRoot sig : {}", sig, self.signature);

//         sig == self.signature
//         // true
//     }

//     pub fn verify(&self, key: Key, app_id: String, secret_name: String, target: &Macaroon, discharges: &[Macaroon]) -> bool {
//         let mut sig = format!("MAC({}, {})", key, self.identifier);
//         println!("Initial sig: {:?}", sig);
//         for caveat in self.caveats.iter() {
//             if let Some(ref vid) = caveat.vid {
//                 println!("Check third party predicate: {:#?}", &caveat);
//                 // let caveat_key = format!("Dec({}, {})", sig, &vid);
//                 let caveat_key = decrypt(&sig, &vid);
//                 println!("Key: {}", caveat_key);
//                 let mut checked = false;
//                 for discharge in discharges {
//                     if discharge.identifier == caveat.cid &&
//                         discharge.verify(caveat_key.clone(), app_id.clone(), secret_name.clone(), target, discharges) {
//                         println!("Verified with {:#?}", discharge);
//                         checked = true;
//                     }
//                 }
//                 if !checked {
//                     println!("Failed to check caveat");
//                     return false;
//                 }
//             } else {
//                 println!("Check first party predicate: {:#?}", &caveat);            
//             }
//             sig = format!("MAC({}, {} :: {})", sig, &caveat.vid.clone().unwrap_or("".to_string()), &caveat.cid);
//             println!("Updated sig: {}", sig);

//         }

//         sig = target.bind_for_request(&sig);
//         println!("Final sig: {}\nRoot sig : {}", sig, self.signature);

//         sig == self.signature
//         // true
//     }

//     pub fn finish(&mut self) {
//         self.signature = self.bind_for_request(&self.signature);
//     }
// }



// /// Get a `CaveatId` from the external service for predicate `predicate`, with
// /// proposed root key `caveat_key`.
// ///
// /// This is either: an encrypted blob requiring no communication (using pub key, or shared secret)
// /// Or an token returned from the service.
// pub fn get_third_party_caveat_id(service_key: &Key, caveat_key: &Key, predicate: Predicate) -> CaveatId {
//     encrypt(&service_key, &format!("{{({}, {})}}", caveat_key, predicate))
// }

// pub fn get_secret_token(key: Key, app_id: String, secret_name: String) -> Macaroon {
//     let identifier = format!("{} || {}", app_id, secret_name);
//     // let key = String::from("root_key");
//     let mut macaroon = Macaroon::new(key, identifier);

//     // let ttl_caveat = Caveat::first_party("expires in 1 hour".to_string());
//     // macaroon.add_caveat(ttl_caveat);
//     let authn_key = "K_authn".to_string();
//     let ckn = "ckn".to_string();
//     let cidn = get_third_party_caveat_id(&authn_key, &ckn, format!("app_id = {}", app_id));
//     let authn_caveat = Caveat::third_party(cidn, ckn, (), &macaroon);
//     macaroon.add_caveat(authn_caveat);

//     let authz_key = "K_authz".to_string();
//     let ckz = "ckz".to_string();
//     let cidz = get_third_party_caveat_id(&authz_key, &ckz, format!("app_id = {} has access to secret_name = {}", app_id, secret_name));
//     let authz_caveat = Caveat::third_party(cidz, ckz, (), &macaroon);
//     macaroon.add_caveat(authz_caveat);

//     macaroon
// }

// pub fn acquire_discharge(location: &Location, caveat_id: &CaveatId) -> Macaroon {
//     let key_pred = decrypt(&"k_loc".to_string(), &caveat_id);
//     let key = key_pred[2..key_pred.len() - 1].splitn(2, ",").nth(0).unwrap().to_string();
//     println!("cK: {}", key);
//     let mut macaroon = Macaroon::new(key, caveat_id.clone());

//     // let ttl_caveat = Caveat::first_party("expires in 1 minute".to_string());
//     // macaroon.add_caveat(ttl_caveat);
//     macaroon
// }

// pub fn get_auth(key: Key, app_id: String, secret_name: String) -> (Macaroon, Vec<Macaroon>) {
//     let mut macaroot = get_secret_token(key, app_id, secret_name);

//     println!("Initial macaroon: {:#?}", &macaroot);
//     let mut discharges = Vec::new();
//     for caveat in macaroot.caveats.iter() {
//         if caveat.is_third_party() {
//             let mut discharge = acquire_discharge(&caveat.cl, &caveat.cid);
//             println!("Discharge: {:#?}", &discharge);
//             macaroot.prepare(&mut discharge);
//             println!("Bound Discharge: {:#?}", &discharge);
//             discharges.push(discharge);
//         }
//     }

//     (macaroot, discharges)
// }


// #[cfg(test)]
// mod test {
//     use super::*;

//     #[test]
//     fn test_macaroon() {
//         let ts_key = String::from("root_key");
//         // let mut macaroon = get_secret_token(ts_key);
//         let (macaroot, discharges) = get_auth(ts_key.clone(), "my_app".to_string(), "password".to_string());

//         println!("Start verifying...");
//         let verified = macaroot.verify_root(ts_key.clone(), "my_app".to_string(), "password".to_string(), &discharges);
//         println!("Finished verifying");
//         println!("{:#?}", &macaroot);
//         println!("{:#?}", &discharges);

//         assert!(verified);
//     }
// }