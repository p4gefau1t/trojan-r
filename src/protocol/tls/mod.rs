use crate::error::Error;
use rustls::internal::pemfile::{certs, pkcs8_private_keys};
use rustls::{Certificate, CipherSuite, PrivateKey, SupportedCipherSuite};
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::path::Path;

pub mod acceptor;
pub mod connector;

fn new_error<T: ToString>(message: T) -> io::Error {
    return Error::new(format!("tls: {}", message.to_string())).into();
}

fn load_cert(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls cert"))
}

fn load_key(path: &Path) -> io::Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls key"))
}

fn get_cipher_name(cipher: &SupportedCipherSuite) -> &'static str {
    /*
    /// A list of all the cipher suites supported by rustls.
    pub static ALL_CIPHERSUITES: [&SupportedCipherSuite; 9] = [
        // TLS1.3 suites
        &TLS13_CHACHA20_POLY1305_SHA256,
        &TLS13_AES_256_GCM_SHA384,
        &TLS13_AES_128_GCM_SHA256,

        // TLS1.2 suites
        &TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        &TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        &TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        &TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ];
     */
    match cipher.suite {
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => "TLS13_CHACHA20_POLY1305_SHA256",
        CipherSuite::TLS13_AES_256_GCM_SHA384 => "TLS13_AES_256_GCM_SHA384",
        CipherSuite::TLS13_AES_128_GCM_SHA256 => "TLS13_AES_128_GCM_SHA256",
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        }
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        }
        _ => "???",
    }
}

fn get_cipher_suite(cipher: Option<Vec<String>>) -> io::Result<Vec<&'static SupportedCipherSuite>> {
    if cipher.is_none() {
        return Ok(rustls::ALL_CIPHERSUITES.to_vec());
    }
    let cipher = cipher.unwrap();
    let mut result = Vec::new();

    for name in cipher {
        let mut found = false;
        for i in rustls::ALL_CIPHERSUITES.to_vec() {
            if name == get_cipher_name(i) {
                result.push(i);
                found = true;
                log::debug!("cipher: {} applied", name);
                break;
            }
        }
        if !found {
            return Err(new_error(format!("bad cipher: {}", name)));
        }
    }
    Ok(result)
}
