use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rcgen::generate_simple_self_signed;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{self, ring},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const DEFAULT_IDENTITY_PATH: &str = "server_tls_identity.json";

#[derive(Deserialize, Serialize)]
struct StoredIdentity {
    certificate_der: String,
    private_key_der: String,
}

pub struct ServerTls {
    pub acceptor: TlsAcceptor,
    pub fingerprint: String,
}

pub fn load_or_create_server_tls() -> Result<ServerTls> {
    let path = std::env::var_os("RUST_PROXY_TLS_IDENTITY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_IDENTITY_PATH));
    let identity = load_or_create_identity(&path)?;
    let certificate = CertificateDer::from(
        STANDARD
            .decode(identity.certificate_der)
            .context("invalid TLS certificate encoding")?,
    );
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        STANDARD
            .decode(identity.private_key_der)
            .context("invalid TLS private key encoding")?,
    ));
    let provider = Arc::new(ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], private_key)?;

    Ok(ServerTls {
        acceptor: TlsAcceptor::from(Arc::new(config)),
        fingerprint: fingerprint(certificate.as_ref()),
    })
}

pub fn client_connector(fingerprint: &str) -> Result<TlsConnector> {
    let provider = Arc::new(ring::default_provider());
    let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(FingerprintVerifier {
            expected: parse_fingerprint(fingerprint)?,
            provider,
        }))
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

pub fn server_name(server_addr: &str) -> Result<ServerName<'static>> {
    let host = if let Some(rest) = server_addr.strip_prefix('[') {
        rest.split_once(']')
            .map(|(host, _)| host)
            .ok_or_else(|| anyhow!("invalid server address"))?
    } else {
        server_addr
            .rsplit_once(':')
            .map(|(host, _)| host)
            .ok_or_else(|| anyhow!("server address must include a port"))?
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        ServerName::try_from(host.to_owned()).map_err(|_| anyhow!("invalid server hostname"))
    }
}

fn load_or_create_identity(path: &Path) -> Result<StoredIdentity> {
    if path.exists() {
        return serde_json::from_slice(&fs::read(path).context("read TLS identity")?)
            .context("parse TLS identity");
    }

    let certified = generate_simple_self_signed(vec!["rustproxy".into()])?;
    let identity = StoredIdentity {
        certificate_der: STANDARD.encode(certified.cert.der()),
        private_key_der: STANDARD.encode(certified.key_pair.serialize_der()),
    };
    let encoded = serde_json::to_vec_pretty(&identity)?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, encoded)?;
    fs::rename(&temporary, path)?;
    Ok(identity)
}

fn fingerprint(certificate: &[u8]) -> String {
    Sha256::digest(certificate)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_fingerprint(value: &str) -> Result<[u8; 32]> {
    let value = value.replace(':', "");
    if !value.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(anyhow!("Server key mismatch"));
    }
    if value.len() != 64 {
        return Err(anyhow!("Server key mismatch"));
    }
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| anyhow!("Server key mismatch"))?;
    }
    Ok(result)
}

#[derive(Debug)]
struct FingerprintVerifier {
    expected: [u8; 32],
    provider: Arc<crypto::CryptoProvider>,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("Server key mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::{fingerprint, parse_fingerprint};

    #[test]
    fn fingerprint_parser_accepts_colons_but_not_short_values() {
        let fingerprint = fingerprint(&[7; 3]);
        assert_eq!(parse_fingerprint(&fingerprint).unwrap().len(), 32);
        assert!(parse_fingerprint("bad").is_err());
    }
}
