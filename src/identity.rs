use crate::{actions::CryptoParameters, prelude::*};

use sha2::Digest as _;

pub struct Identity {
    pub email: String,
    pub keys: crate::locked::Keys,
    pub master_password_hash: crate::locked::PasswordHash,
}

impl Identity {
    pub fn new(
        email: &str,
        password: &crate::locked::Password,
        crypto_params: &CryptoParameters,
    ) -> Result<Self> {
        let email = email.trim().to_lowercase();

        let iterations = std::num::NonZeroU32::new(crypto_params.iterations)
            .ok_or(Error::Pbkdf2ZeroIterations)?;

        let mut keys = crate::locked::LockedVec::new();
        keys.extend(std::iter::repeat_n(0, 64));

        let enc_key = &mut keys[0..32];

        match crypto_params.kdf {
            crate::api::KdfType::Pbkdf2 => {
                pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
                    password.password(),
                    email.as_bytes(),
                    iterations.get(),
                    enc_key,
                )
                .map_err(|_| Error::Pbkdf2)?;
            }

            crate::api::KdfType::Argon2id => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(email.as_bytes());
                let salt = hasher.finalize();

                let argon2_config = argon2::Argon2::new(
                    argon2::Algorithm::Argon2id,
                    argon2::Version::V0x13,
                    argon2::Params::new(
                        crypto_params.memory.unwrap() * 1024,
                        iterations.get(),
                        crypto_params.parallelism.unwrap(),
                        Some(32),
                    )
                    .unwrap(),
                );
                argon2::Argon2::hash_password_into(
                    &argon2_config,
                    password.password(),
                    &salt,
                    enc_key,
                )
                .map_err(|_| Error::Argon2)?;
            }
        }

        let mut hash = crate::locked::LockedVec::new();
        hash.extend(std::iter::repeat_n(0, 32));
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(enc_key, password.password(), 1, &mut hash)
            .map_err(|_| Error::Pbkdf2)?;

        let hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(enc_key).map_err(|_| Error::HkdfExpand)?;
        hkdf.expand(b"enc", enc_key)
            .map_err(|_| Error::HkdfExpand)?;
        let mac_key = &mut keys[32..64];
        hkdf.expand(b"mac", mac_key)
            .map_err(|_| Error::HkdfExpand)?;

        let keys = crate::locked::Keys::new(keys);
        let master_password_hash = crate::locked::PasswordHash::new(hash);

        Ok(Self {
            email: email.clone(),
            keys,
            master_password_hash,
        })
    }
}
