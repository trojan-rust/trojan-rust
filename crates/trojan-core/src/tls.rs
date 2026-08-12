//! Pieces of TLS setup that every role needs the same way.
//!
//! Reading a certificate off disk and skipping peer verification do not vary
//! between the server, the client and the relay transports — but building a
//! `rustls` config does, and deliberately so: the exit server terminates real
//! client TLS with cipher suites, mTLS and session tickets, while a relay hop
//! wraps itself in a throwaway certificate. Those belong to their own crates.
//! Only the parts with one correct implementation live here.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use thiserror::Error;

/// What went wrong reading TLS material off disk.
#[derive(Debug, Error)]
pub enum TlsError {
    /// The file could not be opened or read.
    #[error("failed to read {path}: {source}")]
    Io {
        /// The file that could not be read.
        path: String,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The file parsed, but held nothing of the kind expected.
    #[error("no {kind} found in {path}")]
    Empty {
        /// What was being looked for — "certificate" or "private key".
        kind: &'static str,
        /// The file that held none.
        path: String,
    },
}

/// Read every certificate in a PEM file, leaf first.
///
/// Entries that are not certificates are skipped, so a combined PEM holding a
/// key alongside its chain reads correctly.
pub fn load_certs(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let path = path.as_ref();
    let mut reader = open(path)?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .filter_map(|cert| cert.ok().map(|der| der.into_owned()))
        .collect();

    if certs.is_empty() {
        return Err(TlsError::Empty {
            kind: "certificate",
            path: display(path),
        });
    }
    Ok(certs)
}

/// Read the first private key in a PEM file.
///
/// Accepts both PKCS#8 and PKCS#1, which is what the tooling in the wild
/// produces; anything else in the file is skipped.
pub fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>, TlsError> {
    let path = path.as_ref();
    let mut reader = open(path)?;
    loop {
        let item = rustls_pemfile::read_one(&mut reader).map_err(|source| TlsError::Io {
            path: display(path),
            source,
        })?;
        match item {
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            Some(_) => continue,
            None => {
                return Err(TlsError::Empty {
                    kind: "private key",
                    path: display(path),
                });
            }
        }
    }
}

/// Read a certificate chain and its key together.
pub fn load_keypair(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsError> {
    Ok((load_certs(cert_path)?, load_private_key(key_path)?))
}

fn open(path: &Path) -> Result<BufReader<File>, TlsError> {
    File::open(path)
        .map(BufReader::new)
        .map_err(|source| TlsError::Io {
            path: display(path),
            source,
        })
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

/// A verifier that accepts any server certificate, checking nothing.
///
/// This removes the guarantee TLS exists to provide, so it is only ever
/// correct where the peer is authenticated some other way: relay hops
/// authenticate each other with a pre-shared password over the tunnel, and
/// their certificates are self-signed throwaways no CA could vouch for. Any
/// other use is a man-in-the-middle waiting to happen.
#[derive(Debug)]
pub struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Whatever the installed provider supports, or the built-in one when no
    /// provider has been installed — a binary that forgot to install one would
    /// otherwise advertise no schemes at all and fail every handshake.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        match rustls::crypto::CryptoProvider::get_default() {
            Some(provider) => provider
                .signature_verification_algorithms
                .supported_schemes(),
            None => rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write a self-signed cert and key, returning their paths.
    fn write_keypair(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = CertificateParams::default().self_signed(&key_pair).unwrap();

        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
        (cert_path, key_path)
    }

    #[test]
    fn a_generated_keypair_loads() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = write_keypair(dir.path());

        let (certs, _key) = load_keypair(&cert_path, &key_path).unwrap();

        assert_eq!(certs.len(), 1);
    }

    /// A path typo is the common operator mistake, and it has to name the file
    /// rather than surface as a bare "not found".
    #[test]
    fn a_missing_file_names_itself() {
        let err = load_certs("/nonexistent/cert.pem").unwrap_err();

        assert!(
            matches!(err, TlsError::Io { ref path, .. } if path.contains("cert.pem")),
            "got {err}"
        );
    }

    /// A PEM holding only a key is not a certificate file, and reporting it as
    /// empty beats handing rustls an empty chain to reject later.
    #[test]
    fn a_pem_without_certificates_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (_cert_path, key_path) = write_keypair(dir.path());

        let err = load_certs(&key_path).unwrap_err();

        assert!(matches!(
            err,
            TlsError::Empty {
                kind: "certificate",
                ..
            }
        ));
    }

    #[test]
    fn a_pem_without_a_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, _key_path) = write_keypair(dir.path());

        let err = load_private_key(&cert_path).unwrap_err();

        assert!(matches!(
            err,
            TlsError::Empty {
                kind: "private key",
                ..
            }
        ));
    }

    /// Both encodings are in circulation; openssl emits PKCS#1 by default.
    #[test]
    fn pkcs1_keys_load_too() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("rsa.pem");
        // A minimal PKCS#1 body: the loader must dispatch on the PEM label,
        // not validate the key, so any well-formed base64 body will do.
        let mut file = std::fs::File::create(&key_path).unwrap();
        writeln!(file, "-----BEGIN RSA PRIVATE KEY-----").unwrap();
        writeln!(
            file,
            "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeK"
        )
        .unwrap();
        writeln!(file, "-----END RSA PRIVATE KEY-----").unwrap();
        drop(file);

        let key = load_private_key(&key_path).unwrap();

        assert!(matches!(key, PrivateKeyDer::Pkcs1(_)));
    }
}
