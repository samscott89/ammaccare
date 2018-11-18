extern crate failure;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate sodiumoxide;
extern crate url;

pub mod caveat;
pub mod crypto;
pub mod macaroon;

pub use caveat::Caveat;
pub use macaroon::Macaroon;

pub fn macaroon_key() -> Vec<u8> {
    sodiumoxide::randombytes::randombytes(32)
}
