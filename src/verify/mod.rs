pub mod helpers;

use std::collections::HashMap;

use crate::{
    anyhow::{anyhow, bail},
    crypto::{CoseP256Verifier, Crypto},
    outcome::{ClaimValue, CredentialInfo, Failure, Outcome, Result},
};
use cose_rs::{
    cwt::{claim::ExpirationTime, ClaimsSet},
    sign1::VerificationResult,
    CoseSign1,
};
use num_bigint::BigUint;
use num_traits::Num as _;
use p256::PublicKey;
use ssi::dids::Document;
use ssi_jwk::{Params, JWK};
use ssi_status::token_status_list::{json::JsonStatusList, DecodeError};
use time::OffsetDateTime;
use uniffi::deps::anyhow::Context;
use x509_cert::der::Encode;
use x509_cert::{certificate::CertificateInner, Certificate};

pub trait Credential {
    const TITLE: &'static str;
    const IMAGE: &'static [u8];

    fn schemas() -> Vec<&'static str>;
    fn parse_claims(claims: ClaimsSet) -> Result<HashMap<String, ClaimValue>>;
}

pub fn retrieve_entry_from_status_list(
    status_list: String,
    idx: usize,
) -> Result<u8, crate::anyhow::Error> {
    let status_list: JsonStatusList = serde_json::from_str(status_list.as_str())
        .map_err(|_: serde_json::Error| crate::anyhow::anyhow!("Unable to parse JSON String"))?;
    let bitstring = status_list.decode(None).map_err(|_: DecodeError| {
        crate::anyhow::anyhow!("Unable to decode JsonStatusList bitstring")
    })?;
    bitstring
        .get(idx)
        .ok_or(crate::anyhow::anyhow!("Unable to get idx from bitstring"))
}

pub trait Verifiable: Credential {
    fn decode(&self, qr_code_payload: String) -> Result<(CoseSign1, CredentialInfo)> {
        let base10_str = qr_code_payload.strip_prefix('9').ok_or_else(|| {
            Failure::base10_decoding("payload did not begin with multibase prefix '9'")
        })?;
        let compressed_cwt_bytes = BigUint::from_str_radix(base10_str, 10)
            .map_err(Failure::base10_decoding)?
            .to_bytes_be();

        let cwt_bytes = miniz_oxide::inflate::decompress_to_vec(&compressed_cwt_bytes)
            .map_err(Failure::decompression)?;

        let cwt: CoseSign1 = serde_cbor::from_slice(&cwt_bytes).map_err(Failure::cbor_decoding)?;

        let mut claims = cwt
            .claims_set()
            .map_err(Failure::claims_retrieval)?
            .ok_or_else(Failure::empty_payload)?;

        match claims
            .remove_i(-65537)
            .ok_or_else(|| Failure::missing_claim("Credential Schema"))?
        {
            serde_cbor::Value::Text(s) if Self::schemas().contains(&s.as_str()) => (),
            v => {
                return Err(Failure::incorrect_credential(
                    format!("{:?}", Self::schemas()),
                    v,
                ))
            }
        }

        let claims = Self::parse_claims(claims)?;

        Ok((
            cwt,
            CredentialInfo {
                title: Self::TITLE.to_string(),
                image: Self::IMAGE.to_vec(),
                claims,
            },
        ))
    }

    fn validate<C: Crypto>(
        &self,
        crypto: &C,
        cwt: CoseSign1,
        trusted_roots: Vec<Certificate>,
        did_document: Option<Document>,
    ) -> Result<()> {
        // Check protected header to determine verification method
        let protected = cwt.protected();

        // Check for kid parameter (4) vs x5c parameter (33)
        if protected.get_i(4).is_some() {
            self.validate_did_web(crypto, cwt, did_document)
        } else if protected.get_i(33).is_some() {
            self.validate_x509(crypto, cwt, trusted_roots)
        } else {
            Err(Failure::trust(anyhow!("No supported verification method found in protected header (missing both kid and x5c parameters)")))
        }
    }

    fn validate_x509<C: Crypto>(
        &self,
        crypto: &C,
        cwt: CoseSign1,
        trusted_roots: Vec<Certificate>,
    ) -> Result<()> {
        let signer_certificate = helpers::get_signer_certificate(&cwt).map_err(Failure::trust)?;

        // We want to manually handle the Err to get all errors, so try_fold would not work
        #[allow(clippy::manual_try_fold)]
        trusted_roots
            .into_iter()
            .filter(|cert| {
                cert.tbs_certificate.subject == signer_certificate.tbs_certificate.issuer
            })
            .fold(Result::Err("\n".to_string()), |res, cert| match res {
                Ok(_) => Ok(()),
                Err(err) => match self.validate_certificate_chain(crypto, &cwt, cert.clone()) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(format!("{}\n--------------\n{}", err, e)),
                },
            })
            .map_err(|err| {
                anyhow!(if err == "\n" {
                    format!("signer certificate was not issued by the root:\n\texpected:\n\t\t{}\n\tfound: None.", signer_certificate.tbs_certificate.issuer)
                } else {
                    err
                })
            })
            .map_err(Failure::trust)?;

        self.validate_cwt(cwt)
    }

    /// Validates credentials using did:web verification method.
    /// Extracts kid from COSE header, finds matching verification method in DID document,
    /// and verifies signature using the public key from the verification method's JWK.
    fn validate_did_web<C: Crypto>(
        &self,
        crypto: &C,
        cwt: CoseSign1,
        did_document: Option<Document>,
    ) -> Result<()> {
        let did_document =
            did_document.ok_or_else(|| Failure::trust(anyhow!("DID document not found")))?;

        // Extract kid from protected header
        let kid = cwt
            .protected()
            .get_i(4)
            .and_then(|v| match v {
                serde_cbor::Value::Text(s) => Some(s.clone()),
                serde_cbor::Value::Bytes(b) => {
                    // Try to decode bytes as UTF-8 string
                    String::from_utf8(b.clone()).ok()
                }
                _ => None,
            })
            .ok_or_else(|| {
                Failure::trust(anyhow!("kid parameter not found or not a valid string"))
            })?;

        // Find verification method by kid
        let verification_method = did_document
            .verification_method
            .iter()
            .find(|vm| vm.id.as_str() == did_document.id.to_string() + "#" + &kid)
            .ok_or_else(|| {
                let available_ids: Vec<&str> = did_document
                    .verification_method
                    .iter()
                    .map(|vm| vm.id.as_str())
                    .collect();
                Failure::trust(anyhow!(
                    "verification method with kid '{}' not found in DID document. Available verification methods: {:?}",
                    kid,
                    available_ids
                ))
            })?;

        // Extract public key from verification method
        let public_key = match verification_method.properties.get("publicKeyJwk") {
            Some(jwk_value) => {
                let jwk: JWK = serde_json::from_value(jwk_value.clone())
                    .map_err(|e| Failure::trust(anyhow!("failed to parse JWK: {}", e)))?;

                let key = jwk.to_public();
                let pubkey: PublicKey = if let Params::EC(ec_params) = &key.params {
                    ec_params.try_into().map_err(|e| {
                        Failure::trust(anyhow!("failed to convert ECParams to PublicKey: {}", e))
                    })?
                } else {
                    return Err(Failure::trust(anyhow!("key is not an EC key")));
                };

                pubkey
            }
            None => {
                return Err(Failure::trust(anyhow!(
                    "publicKeyJwk not found in verification method"
                )))
            }
        };

        // Create COSE verifier for did:web that uses the crypto callback
        let verifier = CoseP256Verifier {
            crypto,
            certificate_der: public_key.to_sec1_bytes().to_vec(),
        };

        // Verify the COSE signature
        match cwt.verify(&verifier, None, None) {
            VerificationResult::Success => self.validate_cwt(cwt),
            VerificationResult::Failure(e) => Err(Failure::trust(anyhow!(
                "failed to verify COSE signature: {}",
                e
            ))),
            VerificationResult::Error(e) => Err(Failure::trust(anyhow!(
                "error verifying COSE signature: {}",
                e
            ))),
        }
    }

    fn validate_cwt(&self, cwt: CoseSign1) -> Result<()> {
        let claims = cwt
            .claims_set()
            .map_err(Failure::claims_retrieval)?
            .ok_or_else(Failure::empty_payload)?;

        if let Some(ExpirationTime(exp)) = claims
            .get_claim()
            .map_err(|e| Failure::malformed_claim("exp", &e, "could not parse"))?
        {
            let exp: OffsetDateTime = exp
                .try_into()
                .map_err(|e| Failure::malformed_claim("exp", &e, "could not parse"))?;
            if exp < OffsetDateTime::now_utc() {
                let date_format = time::macros::format_description!("[month]/[day]/[year]");
                let expiration_date_str = exp.format(date_format).map_err(Failure::internal)?;
                return Err(Failure::cwt_expired(expiration_date_str));
            }
        }

        Ok(())
    }

    fn validate_certificate_chain(
        &self,
        crypto: &dyn Crypto,
        cwt: &CoseSign1,
        root_certificate: CertificateInner,
    ) -> crate::anyhow::Result<()> {
        let signer_certificate = helpers::get_signer_certificate(cwt)?;

        // Root validation.
        {
            helpers::check_validity(&root_certificate.tbs_certificate.validity)?;

            let (key_usage, _crl_dp) = helpers::extract_extensions(&root_certificate)
                .context("couldn't extract extensions from root certificate")?;

            if !key_usage.key_cert_sign() {
                bail!("root certificate cannot be used for verifying certificate signatures")
            }

            // TODO: Check crl
        }

        // Validate that Root issued Signer.
        let root_subject = &root_certificate.tbs_certificate.subject;
        let signer_issuer = &signer_certificate.tbs_certificate.issuer;
        if root_subject != signer_issuer {
            bail!("signer certificate was not issued by the root:\n\texpected:\n\t\t{root_subject}\n\tfound:\n\t\t{signer_issuer}")
        }
        let signer_tbs_der = signer_certificate
            .tbs_certificate
            .to_der()
            .context("unable to encode signer certificate as der")?;
        let signer_signature = signer_certificate.signature.raw_bytes().to_vec();
        crypto
            .p256_verify(
                root_certificate
                    .to_der()
                    .context("unable to encode root certificate as der")?,
                signer_tbs_der,
                signer_signature,
            )
            .into_result()
            .map_err(crate::anyhow::Error::msg)
            .context("failed to verify the signature on the signer certificate")?;

        // Signer validation.
        {
            helpers::check_validity(&root_certificate.tbs_certificate.validity)?;

            let (key_usage, _crl_dp) = helpers::extract_extensions(&signer_certificate)
                .context("couldn't extract extensions from signer certificate")?;

            if !key_usage.digital_signature() {
                bail!("signer certificate cannot be used for verifying signatures")
            }

            // TODO: Check crl
        }

        // Validate that Signer issued CWT.
        let verifier = CoseP256Verifier {
            crypto,
            certificate_der: signer_certificate
                .to_der()
                .context("unable to encode signer certificate as der")?,
        };
        match cwt.verify(&verifier, None, None) {
            VerificationResult::Success => Ok(()),
            VerificationResult::Failure(e) => {
                bail!("failed to verify the CWT signature: {e}")
            }
            VerificationResult::Error(e) => {
                Err(e).context("error occurred when verifying CWT signature")
            }
        }
    }

    fn verify<C: Crypto>(
        &self,
        crypto: &C,
        qr_code_payload: String,
        trusted_roots: Vec<Certificate>,
        did_document: Option<Document>,
    ) -> Outcome {
        let (cwt, credential_info) = match self.decode(qr_code_payload) {
            Ok(s) => s,
            Err(f) => {
                return Outcome::Unverified {
                    credential_info: None,
                    failure: f,
                }
            }
        };

        match self.validate(crypto, cwt, trusted_roots, did_document) {
            Ok(()) => Outcome::Verified { credential_info },
            Err(f) => Outcome::Unverified {
                credential_info: Some(credential_info),
                failure: f,
            },
        }
    }
}
