use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use x509_parser::parse_x509_certificate;

/// Official Google Android Hardware Attestation Root CA (RSA-4096).
///
/// Subject: SERIALNUMBER=f92009e853b6b045
/// Re-issued certificate (2022-03-20 .. 2042-03-15) sharing the exact same RSA-4096
/// SubjectPublicKeyInfo as the original 2016 factory-provisioned root.
/// Source: https://android.googleapis.com/attestation/root
pub const GOOGLE_RSA4096_ROOT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----";

/// Official Google Android Hardware Attestation Root CA (ECDSA P-384).
///
/// Subject: CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US
/// Validity: 2025-07-17 .. 2035-07-15 (used by Remote Key Provisioning / modern devices).
/// Source: https://android.googleapis.com/attestation/root
pub const GOOGLE_ECDSA_P384_ROOT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----";

#[derive(Debug, Clone)]
pub struct PinnedRootSpki {
    pub name: &'static str,
    pub spki_der: Vec<u8>,
}

/// Pinned Google Android Hardware Attestation Root CA SubjectPublicKeyInfo (DER) bytes.
pub static GOOGLE_HARDWARE_ROOT_SPKIS: LazyLock<Vec<PinnedRootSpki>> = LazyLock::new(|| {
    vec![
        PinnedRootSpki {
            name: "Google Android Hardware Attestation Root (RSA-4096)",
            spki_der: extract_spki_from_pem(GOOGLE_RSA4096_ROOT_PEM),
        },
        PinnedRootSpki {
            name: "Google Android Key Attestation CA1 (ECDSA P-384)",
            spki_der: extract_spki_from_pem(GOOGLE_ECDSA_P384_ROOT_PEM),
        },
    ]
});

fn extract_spki_from_pem(pem: &str) -> Vec<u8> {
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect();
    let der = STANDARD
        .decode(b64)
        .expect("embedded Google root certificate PEM must decode cleanly");
    let (_, cert) = parse_x509_certificate(&der)
        .expect("embedded Google root certificate DER must parse cleanly");
    cert.verify_signature(None)
        .expect("embedded Google root certificate self-signature must be valid");
    cert.public_key().raw.to_vec()
}

/// Returns the matching pinned root CA name if `spki_der` matches one of Google's
/// official Android Hardware Attestation Root CA public keys.
pub fn match_pinned_google_root(spki_der: &[u8]) -> Option<&'static str> {
    match_spki_in_list(spki_der, &GOOGLE_HARDWARE_ROOT_SPKIS)
}

pub fn match_spki_in_list<'a>(
    spki_der: &[u8],
    roots: &'a [PinnedRootSpki],
) -> Option<&'a str> {
    roots
        .iter()
        .find(|root| root.spki_der.as_slice() == spki_der)
        .map(|root| root.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn embedded_google_roots_parse_and_self_verify() {
        let roots = &*GOOGLE_HARDWARE_ROOT_SPKIS;
        assert_eq!(roots.len(), 2);

        // RSA-4096 SPKI is 550 bytes (DER SubjectPublicKeyInfo for 4096-bit RSA key).
        assert_eq!(roots[0].spki_der.len(), 550);
        // ECDSA P-384 uncompressed SPKI is 120 bytes.
        assert_eq!(roots[1].spki_der.len(), 120);

        // Verify SHA-256 fingerprint of Key Attestation CA1 cert matches Google's published value.
        let b64: String = GOOGLE_ECDSA_P384_ROOT_PEM
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der = STANDARD.decode(b64).unwrap();
        let fp = hex::encode(Sha256::digest(&der));
        assert_eq!(
            fp,
            "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0"
        );
    }
}
