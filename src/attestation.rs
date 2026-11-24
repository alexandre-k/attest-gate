use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use der_parser::asn1_rs::Class;
use der_parser::der::{DerObject, DerObjectContent, parse_der};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::Oid;
use x509_parser::parse_x509_certificate;

use crate::config::Config;
use crate::error::AppError;
use crate::roots::{GOOGLE_HARDWARE_ROOT_SPKIS, PinnedRootSpki, match_spki_in_list};
use crate::state::{ChallengeStore, TrustAnchors, now_unix_secs};
use crate::sync::normalize_hex_serial;

/// Android Key Attestation X.509 Extension OID (`1.3.6.1.4.1.11129.2.1.17`).
pub const KEY_ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

const MAX_CHAIN_LEN: usize = 10;
const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_ATTESTATION_APPLICATION_ID: u32 = 709;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    StrongBox = 2,
}

impl SecurityLevel {
    fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Software),
            1 => Some(Self::TrustedEnvironment),
            2 => Some(Self::StrongBox),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedBootState {
    Verified = 0,
    SelfSigned = 1,
    Unverified = 2,
    Failed = 3,
}

impl VerifiedBootState {
    fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Verified),
            1 => Some(Self::SelfSigned),
            2 => Some(Self::Unverified),
            3 => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    pub root_name: String,
    pub security_level: SecurityLevel,
    pub verified_boot_state: VerifiedBootState,
    pub verified_boot_key_hex: String,
    pub package_name: String,
    pub matched_signing_digest_hex: String,
}

#[derive(Debug)]
struct ParsedKeyDescription {
    attestation_security_level: SecurityLevel,
    keymaster_security_level: SecurityLevel,
    attestation_challenge: Vec<u8>,
    root_of_trust: ParsedRootOfTrust,
    application_id: ParsedApplicationId,
}

#[derive(Debug)]
struct ParsedRootOfTrust {
    verified_boot_key: Vec<u8>,
    device_locked: bool,
    verified_boot_state: VerifiedBootState,
}

#[derive(Debug)]
struct ParsedApplicationId {
    package_names: Vec<String>,
    signature_digests: Vec<Vec<u8>>,
}

/// Runs the complete hardware attestation verification pipeline using Google's pinned root SPKIs.
pub fn verify_attestation(
    challenge_b64url: &str,
    certificate_chain_b64: &[String],
    challenges: &ChallengeStore,
    trust_anchors: &TrustAnchors,
    config: &Config,
) -> Result<VerifiedAttestation, AppError> {
    verify_attestation_with_roots(
        challenge_b64url,
        certificate_chain_b64,
        challenges,
        trust_anchors,
        config,
        &GOOGLE_HARDWARE_ROOT_SPKIS,
    )
}

/// Core verification pipeline accepting explicit pinned root SPKIs (enables deterministic unit testing).
pub fn verify_attestation_with_roots(
    challenge_b64url: &str,
    certificate_chain_b64: &[String],
    challenges: &ChallengeStore,
    trust_anchors: &TrustAnchors,
    config: &Config,
    pinned_roots: &[PinnedRootSpki],
) -> Result<VerifiedAttestation, AppError> {
    // Fail-closed if Google CRL has not been synchronized yet or has gone stale.
    if trust_anchors.crl_last_synced_unix.is_none() {
        return Err(AppError::ServiceUnavailable(
            "Google attestation CRL has not completed initial sync".to_string(),
        ));
    }
    if !trust_anchors.is_crl_fresh(now_unix_secs()) {
        return Err(AppError::ServiceUnavailable(
            "Google attestation CRL is stale and awaiting refresh".to_string(),
        ));
    }

    // 1. Challenge check: atomically remove challenge from DashMap; reject (403) if missing/expired.
    let expected_challenge_bytes = challenges
        .consume(challenge_b64url)
        .ok_or_else(|| AppError::Forbidden("challenge is missing, already used, or expired".to_string()))?;

    // 2. X.509 chain decode, parse, validity, signature verification, and root SPKI pinning.
    if certificate_chain_b64.len() < 2 {
        return Err(AppError::Forbidden(
            "certificate_chain must contain at least 2 certificates (leaf + root)".to_string(),
        ));
    }
    if certificate_chain_b64.len() > MAX_CHAIN_LEN {
        return Err(AppError::BadRequest(format!(
            "certificate_chain exceeds maximum length of {MAX_CHAIN_LEN}"
        )));
    }

    let mut der_certs: Vec<Vec<u8>> = Vec::with_capacity(certificate_chain_b64.len());
    for (idx, b64) in certificate_chain_b64.iter().enumerate() {
        let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        let der = STANDARD.decode(cleaned).map_err(|e| {
            AppError::BadRequest(format!("invalid base64 in certificate_chain[{idx}]: {e}"))
        })?;
        der_certs.push(der);
    }

    let mut certs: Vec<X509Certificate<'_>> = Vec::with_capacity(der_certs.len());
    for (idx, der) in der_certs.iter().enumerate() {
        let (rem, cert) = parse_x509_certificate(der).map_err(|e| {
            AppError::Forbidden(format!("failed to parse X.509 certificate[{idx}]: {e}"))
        })?;
        if !rem.is_empty() {
            return Err(AppError::Forbidden(format!(
                "trailing bytes after X.509 certificate[{idx}]"
            )));
        }
        certs.push(cert);
    }

    // Check validity periods (non-root certs) and CRL revocation status (all certs).
    //
    // Per Google's Android Key Attestation verifier guidance, do NOT reject the pinned
    // root trust anchor (`certs.last()`) solely for `notAfter` expiration: factory-burned
    // devices (e.g. Pixel 6a / pre-RKP chains) embed the 2016–2026 RSA-4096 root cert
    // (`SERIALNUMBER=f92009e853b6b045`), which shares the exact same SPKI as Google's
    // re-issued 2022–2042 root and is verified via SPKI pinning + Google CRL checks below.
    let root_idx = certs.len() - 1;
    for (idx, cert) in certs.iter().enumerate() {
        if idx < root_idx && !cert.validity().is_valid() {
            return Err(AppError::Forbidden(format!(
                "certificate[{idx}] is expired or not yet valid"
            )));
        }

        // 3. CRL check: lowercase hex serial number (without leading zeros) against Google's feed.
        let serial_hex = normalize_hex_serial(&cert.serial.to_str_radix(16));
        if trust_anchors.revoked_serials.contains(&serial_hex) {
            return Err(AppError::Forbidden(format!(
                "certificate[{idx}] (serial {serial_hex}) is REVOKED or SUSPENDED in Google CRL"
            )));
        }
    }

    // Ensure leaf cert[0] is an end-entity certificate (never a CA or cert-signing key).
    let leaf = &certs[0];
    match leaf.basic_constraints() {
        Ok(Some(bc)) if bc.value.ca => {
            return Err(AppError::Forbidden(
                "leaf certificate[0] must not have BasicConstraints CA=TRUE".to_string(),
            ));
        }
        Err(e) => {
            return Err(AppError::Forbidden(format!(
                "invalid BasicConstraints on leaf certificate[0]: {e}"
            )));
        }
        _ => {}
    }
    match leaf.key_usage() {
        Ok(Some(ku)) if ku.value.key_cert_sign() => {
            return Err(AppError::Forbidden(
                "leaf certificate[0] must not have KeyUsage keyCertSign".to_string(),
            ));
        }
        Err(e) => {
            return Err(AppError::Forbidden(format!(
                "invalid KeyUsage on leaf certificate[0]: {e}"
            )));
        }
        _ => {}
    }

    // Verify certificate chain signatures and strict CA constraints from cert[0] up to cert[n - 1].
    for i in 0..(certs.len() - 1) {
        let issuer_idx = i + 1;
        let child = &certs[i];
        let issuer = &certs[issuer_idx];

        if child.issuer() != issuer.subject() {
            return Err(AppError::Forbidden(format!(
                "certificate[{i}] issuer does not match certificate[{issuer_idx}] subject"
            )));
        }

        // RFC 5280 §4.2.1.9: every issuer certificate MUST explicitly carry BasicConstraints
        // with cA=TRUE and satisfy pathLenConstraint. Allowing missing BasicConstraints would
        // let an end-entity Android Keystore leaf cert act as a fake intermediate CA.
        let bc = issuer
            .basic_constraints()
            .map_err(|e| {
                AppError::Forbidden(format!(
                    "invalid BasicConstraints on certificate[{issuer_idx}]: {e}"
                ))
            })?
            .ok_or_else(|| {
                AppError::Forbidden(format!(
                    "certificate[{issuer_idx}] is missing required BasicConstraints extension"
                ))
            })?;
        if !bc.value.ca {
            return Err(AppError::Forbidden(format!(
                "certificate[{issuer_idx}] is not a CA certificate"
            )));
        }
        if let Some(max_path_len) = bc.value.path_len_constraint {
            let intermediate_cas_below = (issuer_idx - 1) as u32;
            if intermediate_cas_below > max_path_len {
                return Err(AppError::Forbidden(format!(
                    "certificate[{issuer_idx}] violates pathLenConstraint ({intermediate_cas_below} > {max_path_len})"
                )));
            }
        }

        // RFC 5280 §4.2.1.3: every CA certificate MUST include KeyUsage with keyCertSign set.
        let ku = issuer
            .key_usage()
            .map_err(|e| {
                AppError::Forbidden(format!(
                    "invalid KeyUsage on certificate[{issuer_idx}]: {e}"
                ))
            })?
            .ok_or_else(|| {
                AppError::Forbidden(format!(
                    "certificate[{issuer_idx}] is missing required KeyUsage extension"
                ))
            })?;
        if !ku.value.key_cert_sign() {
            return Err(AppError::Forbidden(format!(
                "certificate[{issuer_idx}] KeyUsage does not permit keyCertSign"
            )));
        }

        child
            .verify_signature(Some(issuer.public_key()))
            .map_err(|e| {
                AppError::Forbidden(format!(
                    "signature verification failed for certificate[{i}] against certificate[{issuer_idx}]: {e}"
                ))
            })?;
    }

    // Verify root self-signature and pin SubjectPublicKeyInfo against Google's official hardware roots.
    let root = certs.last().expect("chain length >= 2 checked above");
    if root.issuer() != root.subject() {
        return Err(AppError::Forbidden(
            "root certificate is not self-issued".to_string(),
        ));
    }
    root.verify_signature(Some(root.public_key())).map_err(|e| {
        AppError::Forbidden(format!("root certificate self-signature invalid: {e}"))
    })?;

    let root_name = match_spki_in_list(root.public_key().raw, pinned_roots).ok_or_else(|| {
        AppError::Forbidden(
            "root certificate SubjectPublicKeyInfo does not match pinned Google hardware roots"
                .to_string(),
        )
    })?;

    // 4. Parse ASN.1 KeyDescription extension (OID 1.3.6.1.4.1.11129.2.1.17) from leaf cert[0].
    let attestation_oid = Oid::from_str(KEY_ATTESTATION_OID)
        .expect("static KEY_ATTESTATION_OID must parse");

    let ext = leaf
        .extensions()
        .iter()
        .find(|e| e.oid == attestation_oid)
        .ok_or_else(|| {
            AppError::Forbidden(format!(
                "leaf certificate is missing Android Key Attestation extension ({KEY_ATTESTATION_OID})"
            ))
        })?;

    let key_desc = parse_key_description(ext.value)?;

    // 4a. Verify attestationChallenge equals the consumed challenge bytes (constant-time).
    if !constant_time_eq(&key_desc.attestation_challenge, &expected_challenge_bytes) {
        return Err(AppError::Forbidden(
            "attestationChallenge does not match issued challenge nonce".to_string(),
        ));
    }

    // 4b. Require hardware-backed attestationSecurityLevel and keymasterSecurityLevel >= 1
    // (TEE or StrongBox; reject Software).
    if (key_desc.attestation_security_level as u8) < 1 {
        return Err(AppError::Forbidden(
            "software-backed attestation (securityLevel=0) is rejected; hardware TEE/StrongBox required"
                .to_string(),
        ));
    }
    if (key_desc.keymaster_security_level as u8) < 1 {
        return Err(AppError::Forbidden(
            "software-backed keymaster (keymasterSecurityLevel=0) is rejected; hardware TEE/StrongBox required"
                .to_string(),
        ));
    }

    // 4c. Verify RootOfTrust (from teeEnforced).
    if !key_desc.root_of_trust.device_locked {
        return Err(AppError::Forbidden(
            "device bootloader is unlocked (deviceLocked == false)".to_string(),
        ));
    }

    if key_desc.root_of_trust.verified_boot_key.is_empty()
        || key_desc
            .root_of_trust
            .verified_boot_key
            .iter()
            .all(|&b| b == 0)
    {
        return Err(AppError::Forbidden(
            "RootOfTrust.verifiedBootKey is empty or all-zero".to_string(),
        ));
    }

    let vbk_hex = hex::encode(&key_desc.root_of_trust.verified_boot_key);
    match key_desc.root_of_trust.verified_boot_state {
        VerifiedBootState::Verified => {}
        VerifiedBootState::SelfSigned => {
            if !config.allow_grapheneos {
                return Err(AppError::Forbidden(
                    "SelfSigned verifiedBootState rejected because ALLOW_GRAPHENEOS=false"
                        .to_string(),
                ));
            }
            if trust_anchors.grapheneos_last_synced_unix.is_none() {
                return Err(AppError::ServiceUnavailable(
                    "GrapheneOS verified boot keys have not completed initial sync".to_string(),
                ));
            }
            if !trust_anchors.grapheneos_keys.contains(&vbk_hex) {
                return Err(AppError::Forbidden(
                    "SelfSigned verifiedBootKey is not an official GrapheneOS release key"
                        .to_string(),
                ));
            }
        }
        VerifiedBootState::Unverified => {
            return Err(AppError::Forbidden(
                "verifiedBootState is Unverified (2)".to_string(),
            ));
        }
        VerifiedBootState::Failed => {
            return Err(AppError::Forbidden(
                "verifiedBootState is Failed (3)".to_string(),
            ));
        }
    }

    // 4d. Verify attestationApplicationId ([709]): packageName & APK signing cert SHA-256 digest.
    let matched_pkg = key_desc
        .application_id
        .package_names
        .iter()
        .find(|pkg| pkg.as_str() == config.allowed_package_name)
        .cloned()
        .ok_or_else(|| {
            AppError::Forbidden(
                "attestationApplicationId packageName does not match ALLOWED_PACKAGE_NAME"
                    .to_string(),
            )
        })?;

    let matched_digest = key_desc
        .application_id
        .signature_digests
        .iter()
        .map(hex::encode)
        .find(|digest_hex| config.allowed_signing_cert_sha256.contains(digest_hex))
        .ok_or_else(|| {
            AppError::Forbidden(
                "attestationApplicationId signing certificate SHA-256 does not match ALLOWED_SIGNING_CERT_SHA256"
                    .to_string(),
            )
        })?;

    Ok(VerifiedAttestation {
        root_name: root_name.to_string(),
        security_level: key_desc.attestation_security_level,
        verified_boot_state: key_desc.root_of_trust.verified_boot_state,
        verified_boot_key_hex: vbk_hex,
        package_name: matched_pkg,
        matched_signing_digest_hex: matched_digest,
    })
}

fn parse_key_description(der_bytes: &[u8]) -> Result<ParsedKeyDescription, AppError> {
    let (_, root_obj) = parse_der(der_bytes).map_err(|e| {
        AppError::Forbidden(format!("failed to parse KeyDescription ASN.1 DER: {e}"))
    })?;

    let items = root_obj.as_sequence().map_err(|e| {
        AppError::Forbidden(format!("KeyDescription must be an ASN.1 SEQUENCE: {e}"))
    })?;

    if items.len() < 8 {
        return Err(AppError::Forbidden(format!(
            "KeyDescription SEQUENCE expected 8 elements, found {}",
            items.len()
        )));
    }

    // [0] attestationVersion INTEGER (verified parseable)
    let _attestation_version = parse_asn1_int(&items[0], "attestationVersion")?;

    // [1] attestationSecurityLevel ENUMERATED
    let sec_level_raw = parse_asn1_enum(&items[1], "attestationSecurityLevel")?;
    let attestation_security_level = SecurityLevel::from_u64(sec_level_raw).ok_or_else(|| {
        AppError::Forbidden(format!(
            "unknown attestationSecurityLevel value {sec_level_raw}"
        ))
    })?;

    // [2] keymasterVersion INTEGER
    let _keymaster_version = parse_asn1_int(&items[2], "keymasterVersion")?;

    // [3] keymasterSecurityLevel ENUMERATED
    let km_sec_level_raw = parse_asn1_enum(&items[3], "keymasterSecurityLevel")?;
    let keymaster_security_level = SecurityLevel::from_u64(km_sec_level_raw).ok_or_else(|| {
        AppError::Forbidden(format!(
            "unknown keymasterSecurityLevel value {km_sec_level_raw}"
        ))
    })?;

    // [4] attestationChallenge OCTET STRING
    let attestation_challenge = items[4]
        .as_slice()
        .map_err(|e| AppError::Forbidden(format!("invalid attestationChallenge: {e}")))?
        .to_vec();

    // [5] uniqueId OCTET STRING (present, may be empty)
    let _unique_id = items[5]
        .as_slice()
        .map_err(|e| AppError::Forbidden(format!("invalid uniqueId: {e}")))?;

    // [6] softwareEnforced AuthorizationList
    let software_enforced = items[6].as_sequence().map_err(|e| {
        AppError::Forbidden(format!("softwareEnforced must be a SEQUENCE: {e}"))
    })?;

    // [7] teeEnforced AuthorizationList
    let tee_enforced = items[7].as_sequence().map_err(|e| {
        AppError::Forbidden(format!("teeEnforced must be a SEQUENCE: {e}"))
    })?;

    // RootOfTrust ([704]) MUST come from teeEnforced (never trust softwareEnforced for RootOfTrust).
    let root_of_trust_raw = find_context_tag(tee_enforced, TAG_ROOT_OF_TRUST).ok_or_else(|| {
        AppError::Forbidden(
            "RootOfTrust ([704]) is missing from teeEnforced AuthorizationList".to_string(),
        )
    })?;
    let root_of_trust = parse_root_of_trust(root_of_trust_raw)?;

    // attestationApplicationId ([709]) is placed by Android Keystore in softwareEnforced
    // (or teeEnforced on certain implementations). Check teeEnforced first, then softwareEnforced.
    let app_id_raw = find_context_tag(tee_enforced, TAG_ATTESTATION_APPLICATION_ID)
        .or_else(|| find_context_tag(software_enforced, TAG_ATTESTATION_APPLICATION_ID))
        .ok_or_else(|| {
            AppError::Forbidden(
                "attestationApplicationId ([709]) is missing from AuthorizationList".to_string(),
            )
        })?;
    let application_id = parse_attestation_application_id(app_id_raw)?;

    Ok(ParsedKeyDescription {
        attestation_security_level,
        keymaster_security_level,
        attestation_challenge,
        root_of_trust,
        application_id,
    })
}

fn find_context_tag<'a>(list: &'a [DerObject<'a>], tag_num: u32) -> Option<&'a [u8]> {
    for obj in list {
        if obj.header.class() == Class::ContextSpecific && obj.header.tag().0 == tag_num {
            if let Ok(inner_bytes) = obj.content.as_slice() {
                return Some(inner_bytes);
            }
        }
    }
    None
}

fn parse_root_of_trust(explicit_inner: &[u8]) -> Result<ParsedRootOfTrust, AppError> {
    let (_, seq_obj) = parse_der(explicit_inner)
        .map_err(|e| AppError::Forbidden(format!("failed to parse RootOfTrust DER: {e}")))?;
    let fields = seq_obj
        .as_sequence()
        .map_err(|e| AppError::Forbidden(format!("RootOfTrust must be a SEQUENCE: {e}")))?;

    if fields.len() < 3 {
        return Err(AppError::Forbidden(format!(
            "RootOfTrust expected at least 3 fields, found {}",
            fields.len()
        )));
    }

    let verified_boot_key = fields[0]
        .as_slice()
        .map_err(|e| AppError::Forbidden(format!("invalid RootOfTrust.verifiedBootKey: {e}")))?
        .to_vec();

    let device_locked = fields[1]
        .as_bool()
        .map_err(|e| AppError::Forbidden(format!("invalid RootOfTrust.deviceLocked: {e}")))?;

    let boot_state_raw = parse_asn1_enum(&fields[2], "RootOfTrust.verifiedBootState")?;
    let verified_boot_state = VerifiedBootState::from_u64(boot_state_raw).ok_or_else(|| {
        AppError::Forbidden(format!("unknown verifiedBootState value {boot_state_raw}"))
    })?;

    Ok(ParsedRootOfTrust {
        verified_boot_key,
        device_locked,
        verified_boot_state,
    })
}

fn parse_attestation_application_id(explicit_inner: &[u8]) -> Result<ParsedApplicationId, AppError> {
    // [709] EXPLICIT OCTET STRING wrapping a DER-encoded AttestationApplicationId SEQUENCE.
    let (_, octet_obj) = parse_der(explicit_inner).map_err(|e| {
        AppError::Forbidden(format!(
            "failed to parse attestationApplicationId outer OCTET STRING: {e}"
        ))
    })?;
    let inner_der = octet_obj.as_slice().map_err(|e| {
        AppError::Forbidden(format!(
            "attestationApplicationId ([709]) must wrap an OCTET STRING: {e}"
        ))
    })?;

    let (_, app_id_seq) = parse_der(inner_der).map_err(|e| {
        AppError::Forbidden(format!(
            "failed to parse inner AttestationApplicationId DER SEQUENCE: {e}"
        ))
    })?;
    let fields = app_id_seq.as_sequence().map_err(|e| {
        AppError::Forbidden(format!(
            "inner AttestationApplicationId must be a SEQUENCE: {e}"
        ))
    })?;

    if fields.len() < 2 {
        return Err(AppError::Forbidden(format!(
            "AttestationApplicationId expected 2 elements, found {}",
            fields.len()
        )));
    }

    // [0] package_infos SET OF AttestationPackageInfo
    let pkg_set = match &fields[0].content {
        DerObjectContent::Set(items) => items,
        _ => {
            return Err(AppError::Forbidden(
                "AttestationApplicationId.package_infos must be an ASN.1 SET".to_string(),
            ));
        }
    };

    let mut package_names = Vec::with_capacity(pkg_set.len());
    for pkg_info in pkg_set {
        let pkg_fields = pkg_info.as_sequence().map_err(|e| {
            AppError::Forbidden(format!("AttestationPackageInfo must be a SEQUENCE: {e}"))
        })?;
        if pkg_fields.is_empty() {
            return Err(AppError::Forbidden(
                "AttestationPackageInfo SEQUENCE is empty".to_string(),
            ));
        }
        let name_bytes = pkg_fields[0].as_slice().map_err(|e| {
            AppError::Forbidden(format!("invalid AttestationPackageInfo.package_name: {e}"))
        })?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|e| {
                AppError::Forbidden(format!(
                    "AttestationPackageInfo.package_name is not valid UTF-8: {e}"
                ))
            })?
            .to_string();
        package_names.push(name);
    }

    // [1] signature_digests SET OF OCTET STRING
    let sig_set = match &fields[1].content {
        DerObjectContent::Set(items) => items,
        _ => {
            return Err(AppError::Forbidden(
                "AttestationApplicationId.signature_digests must be an ASN.1 SET".to_string(),
            ));
        }
    };

    let mut signature_digests = Vec::with_capacity(sig_set.len());
    for digest_obj in sig_set {
        let digest_bytes = digest_obj.as_slice().map_err(|e| {
            AppError::Forbidden(format!(
                "invalid OCTET STRING in signature_digests: {e}"
            ))
        })?;
        signature_digests.push(digest_bytes.to_vec());
    }

    Ok(ParsedApplicationId {
        package_names,
        signature_digests,
    })
}

fn parse_asn1_int(obj: &DerObject<'_>, field: &str) -> Result<i64, AppError> {
    obj.as_i64()
        .map_err(|e| AppError::Forbidden(format!("invalid ASN.1 INTEGER for {field}: {e}")))
}

fn parse_asn1_enum(obj: &DerObject<'_>, field: &str) -> Result<u64, AppError> {
    match obj.content {
        DerObjectContent::Enum(v) => Ok(v),
        DerObjectContent::Integer(_) => obj
            .as_u64()
            .map_err(|e| AppError::Forbidden(format!("invalid ASN.1 ENUMERATED for {field}: {e}"))),
        _ => Err(AppError::Forbidden(format!(
            "expected ASN.1 ENUMERATED for {field}"
        ))),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::time::Duration;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa,
        KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, SerialNumber,
    };

    use crate::config::{ProxyIpMode, ServiceAccountCredentials};

    // Minimal DER builder helpers for constructing authentic KeyDescription extensions in tests.
    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len <= 0xFF {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
        }
    }

    fn der_tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(tag);
        out.extend_from_slice(&der_len(content.len()));
        out.extend_from_slice(content);
        out
    }

    fn der_int(val: u8) -> Vec<u8> {
        der_tlv(&[0x02], &[val])
    }

    fn der_enum(val: u8) -> Vec<u8> {
        der_tlv(&[0x0A], &[val])
    }

    fn der_bool(val: bool) -> Vec<u8> {
        der_tlv(&[0x01], &[if val { 0xFF } else { 0x00 }])
    }

    fn der_octet(bytes: &[u8]) -> Vec<u8> {
        der_tlv(&[0x04], bytes)
    }

    fn der_seq(parts: &[Vec<u8>]) -> Vec<u8> {
        let content: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
        der_tlv(&[0x30], &content)
    }

    fn der_set(parts: &[Vec<u8>]) -> Vec<u8> {
        let content: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
        der_tlv(&[0x31], &content)
    }

    /// Context-specific constructed high-tag-number encoding (X.690 §8.1.2.4.2).
    /// 704 = 0b101_1000000 => [0xBF, 0x85, 0x40]
    /// 709 = 0b101_1000101 => [0xBF, 0x85, 0x45]
    fn der_ctx_explicit(tag_num: u32, inner: &[u8]) -> Vec<u8> {
        let mut tag = vec![0xBF];
        let mut chunks = Vec::new();
        let mut n = tag_num;
        chunks.push((n & 0x7F) as u8);
        n >>= 7;
        while n > 0 {
            chunks.push(((n & 0x7F) as u8) | 0x80);
            n >>= 7;
        }
        chunks.reverse();
        tag.extend_from_slice(&chunks);
        der_tlv(&tag, inner)
    }

    fn build_key_description_der(
        sec_level: u8,
        challenge: &[u8],
        vbk: &[u8],
        device_locked: bool,
        boot_state: u8,
        package_name: &str,
        signing_digest: &[u8],
    ) -> Vec<u8> {
        let pkg_info = der_seq(&[der_octet(package_name.as_bytes()), der_int(1)]);
        let app_id_inner = der_seq(&[der_set(&[pkg_info]), der_set(&[der_octet(signing_digest)])]);
        let sw_enforced = der_seq(&[der_ctx_explicit(709, &der_octet(&app_id_inner))]);

        let rot = der_seq(&[der_octet(vbk), der_bool(device_locked), der_enum(boot_state)]);
        let tee_enforced = der_seq(&[der_ctx_explicit(704, &rot)]);

        der_seq(&[
            der_int(100),        // attestationVersion (KeyMint 1)
            der_enum(sec_level), // attestationSecurityLevel
            der_int(100),        // keymasterVersion
            der_enum(sec_level), // keymasterSecurityLevel
            der_octet(challenge),
            der_octet(&[]),
            sw_enforced,
            tee_enforced,
        ])
    }

    fn test_config(allow_grapheneos: bool, pkg: &str, sig_hex: &str) -> Config {
        let mut digests = HashSet::new();
        digests.insert(sig_hex.to_string());
        Config {
            google_application_credentials: PathBuf::from("/tmp/sa.json"),
            service_account: ServiceAccountCredentials {
                client_email: "test@example.iam.gserviceaccount.com".into(),
                private_key: "unused".into(),
                private_key_id: None,
                token_uri: "https://oauth2.googleapis.com/token".into(),
            },
            firebase_project_number: "123456789".into(),
            firebase_app_id: "1:123456789:android:abcdef".into(),
            allowed_package_name: pkg.into(),
            allowed_signing_cert_sha256: digests,
            allow_grapheneos,
            bind_addr: "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            rate_limit_rpm: 60,
            rate_limit_burst: 20,
            proxy_ip_mode: ProxyIpMode::Direct,
            firebase_api_base: "https://firebaseappcheck.googleapis.com".into(),
        }
    }

    fn build_test_chain(
        ext_der: Vec<u8>,
        leaf_serial: u64,
    ) -> (Vec<String>, Vec<PinnedRootSpki>) {
        // Root CA (ECDSA P-384)
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut root_dn = DistinguishedName::new();
        root_dn.push(DnType::CommonName, "Test Hardware Root CA");
        root_params.distinguished_name = root_dn;
        root_params.serial_number = Some(SerialNumber::from(0x1001u64));
        let root_cert = root_params.self_signed(&root_key).unwrap();

        // Intermediate CA (ECDSA P-256)
        let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut inter_params = CertificateParams::default();
        inter_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        inter_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let mut inter_dn = DistinguishedName::new();
        inter_dn.push(DnType::CommonName, "Test Attestation Intermediate");
        inter_params.distinguished_name = inter_dn;
        inter_params.serial_number = Some(SerialNumber::from(0x2002u64));
        let inter_cert = inter_params
            .signed_by(&inter_key, &root_cert, &root_key)
            .unwrap();

        // Leaf attestation cert with KeyDescription extension
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = CertificateParams::default();
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let mut leaf_dn = DistinguishedName::new();
        leaf_dn.push(DnType::CommonName, "Android Keystore Key");
        leaf_params.distinguished_name = leaf_dn;
        leaf_params.serial_number = Some(SerialNumber::from(leaf_serial));
        leaf_params.custom_extensions.push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            ext_der,
        ));
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &inter_cert, &inter_key)
            .unwrap();

        let (_, parsed_root) = parse_x509_certificate(root_cert.der()).unwrap();
        let pinned = vec![PinnedRootSpki {
            name: "Test Hardware Root CA",
            spki_der: parsed_root.public_key().raw.to_vec(),
        }];

        let chain_b64 = vec![
            STANDARD.encode(leaf_cert.der()),
            STANDARD.encode(inter_cert.der()),
            STANDARD.encode(root_cert.der()),
        ];

        (chain_b64, pinned)
    }

    #[test]
    fn accepts_valid_stock_android_strongbox_attestation_and_prevents_replay() {
        let store = ChallengeStore::new();
        let (challenge, _) = store.issue().unwrap();
        let challenge_bytes = URL_SAFE_NO_PAD.decode(&challenge).unwrap();

        let signing_digest = [0xABu8; 32];
        let signing_hex = hex::encode(signing_digest);
        let vbk = [0x11u8; 32];

        let ext = build_key_description_der(
            2, // StrongBox
            &challenge_bytes,
            &vbk,
            true,
            0, // Verified (stock Android)
            "com.example.app",
            &signing_digest,
        );
        let (chain, pinned) = build_test_chain(ext, 0x3003);

        let anchors = TrustAnchors {
            crl_last_synced_unix: Some(now_unix_secs()),
            ..Default::default()
        };
        let cfg = test_config(true, "com.example.app", &signing_hex);

        let verified =
            verify_attestation_with_roots(&challenge, &chain, &store, &anchors, &cfg, &pinned)
                .unwrap();
        assert_eq!(verified.security_level, SecurityLevel::StrongBox);
        assert_eq!(verified.verified_boot_state, VerifiedBootState::Verified);
        assert_eq!(verified.package_name, "com.example.app");

        // Replay of the same challenge MUST fail (single-use atomic deletion).
        let replay =
            verify_attestation_with_roots(&challenge, &chain, &store, &anchors, &cfg, &pinned);
        assert!(matches!(replay, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn accepts_grapheneos_self_signed_only_when_enabled_and_key_trusted() {
        let signing_digest = [0xCDu8; 32];
        let signing_hex = hex::encode(signing_digest);
        let graphene_vbk = [0x42u8; 32];
        let graphene_vbk_hex = hex::encode(graphene_vbk);

        let now = now_unix_secs();
        let mut anchors = TrustAnchors {
            crl_last_synced_unix: Some(now),
            grapheneos_last_synced_unix: Some(now),
            grapheneos_timestamp: 1_776_709_772,
            ..Default::default()
        };
        anchors.grapheneos_keys.insert(graphene_vbk_hex);

        // 1. Succeeds when ALLOW_GRAPHENEOS=true and key matches.
        let store = ChallengeStore::new();
        let (ch1, _) = store.issue().unwrap();
        let ext1 = build_key_description_der(
            1, // TrustedEnvironment
            &URL_SAFE_NO_PAD.decode(&ch1).unwrap(),
            &graphene_vbk,
            true,
            1, // SelfSigned
            "com.example.app",
            &signing_digest,
        );
        let (chain1, pinned1) = build_test_chain(ext1, 0x3004);
        let cfg_allow = test_config(true, "com.example.app", &signing_hex);
        let res = verify_attestation_with_roots(&ch1, &chain1, &store, &anchors, &cfg_allow, &pinned1);
        assert!(res.is_ok());

        // 2. Fails when ALLOW_GRAPHENEOS=false.
        let (ch2, _) = store.issue().unwrap();
        let ext2 = build_key_description_der(
            1,
            &URL_SAFE_NO_PAD.decode(&ch2).unwrap(),
            &graphene_vbk,
            true,
            1,
            "com.example.app",
            &signing_digest,
        );
        let (chain2, pinned2) = build_test_chain(ext2, 0x3005);
        let cfg_deny = test_config(false, "com.example.app", &signing_hex);
        let res2 = verify_attestation_with_roots(&ch2, &chain2, &store, &anchors, &cfg_deny, &pinned2);
        assert!(matches!(res2, Err(AppError::Forbidden(_))));

        // 3. Fails when SelfSigned key is unknown (custom unsigned ROM).
        let (ch3, _) = store.issue().unwrap();
        let ext3 = build_key_description_der(
            1,
            &URL_SAFE_NO_PAD.decode(&ch3).unwrap(),
            &[0x99u8; 32],
            true,
            1,
            "com.example.app",
            &signing_digest,
        );
        let (chain3, pinned3) = build_test_chain(ext3, 0x3006);
        let res3 = verify_attestation_with_roots(&ch3, &chain3, &store, &anchors, &cfg_allow, &pinned3);
        assert!(matches!(res3, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn rejects_software_level_unlocked_bootloader_revoked_serial_and_wrong_app() {
        let signing_digest = [0xEFu8; 32];
        let signing_hex = hex::encode(signing_digest);
        let cfg = test_config(true, "com.example.app", &signing_hex);
        let mut anchors = TrustAnchors {
            crl_last_synced_unix: Some(now_unix_secs()),
            ..Default::default()
        };
        anchors.revoked_serials.insert("deadbeef".to_string());

        let store = ChallengeStore::new();

        // Software security level (0) -> rejected.
        let (ch, _) = store.issue().unwrap();
        let ext = build_key_description_der(
            0,
            &URL_SAFE_NO_PAD.decode(&ch).unwrap(),
            &[1u8; 32],
            true,
            0,
            "com.example.app",
            &signing_digest,
        );
        let (chain, pinned) = build_test_chain(ext, 0x3007);
        assert!(matches!(
            verify_attestation_with_roots(&ch, &chain, &store, &anchors, &cfg, &pinned),
            Err(AppError::Forbidden(_))
        ));

        // Unlocked bootloader -> rejected.
        let (ch, _) = store.issue().unwrap();
        let ext = build_key_description_der(
            1,
            &URL_SAFE_NO_PAD.decode(&ch).unwrap(),
            &[1u8; 32],
            false,
            0,
            "com.example.app",
            &signing_digest,
        );
        let (chain, pinned) = build_test_chain(ext, 0x3008);
        assert!(matches!(
            verify_attestation_with_roots(&ch, &chain, &store, &anchors, &cfg, &pinned),
            Err(AppError::Forbidden(_))
        ));

        // Revoked serial in Google CRL -> rejected.
        let (ch, _) = store.issue().unwrap();
        let ext = build_key_description_der(
            1,
            &URL_SAFE_NO_PAD.decode(&ch).unwrap(),
            &[1u8; 32],
            true,
            0,
            "com.example.app",
            &signing_digest,
        );
        let (chain, pinned) = build_test_chain(ext, 0xdeadbeef);
        assert!(matches!(
            verify_attestation_with_roots(&ch, &chain, &store, &anchors, &cfg, &pinned),
            Err(AppError::Forbidden(_))
        ));

        // Wrong package name -> rejected.
        let (ch, _) = store.issue().unwrap();
        let ext = build_key_description_der(
            1,
            &URL_SAFE_NO_PAD.decode(&ch).unwrap(),
            &[1u8; 32],
            true,
            0,
            "com.evil.clone",
            &signing_digest,
        );
        let (chain, pinned) = build_test_chain(ext, 0x3009);
        assert!(matches!(
            verify_attestation_with_roots(&ch, &chain, &store, &anchors, &cfg, &pinned),
            Err(AppError::Forbidden(_))
        ));

        // Expired challenge -> rejected.
        let expired_ch = URL_SAFE_NO_PAD.encode([7u8; 32]);
        store.insert_with_ttl(expired_ch.clone(), Duration::ZERO);
        let ext = build_key_description_der(
            1,
            &[7u8; 32],
            &[1u8; 32],
            true,
            0,
            "com.example.app",
            &signing_digest,
        );
        let (chain, pinned) = build_test_chain(ext, 0x3010);
        std::thread::sleep(Duration::from_millis(5));
        assert!(matches!(
            verify_attestation_with_roots(&expired_ch, &chain, &store, &anchors, &cfg, &pinned),
            Err(AppError::Forbidden(_))
        ));
    }

    #[test]
    fn allows_expired_pinned_root_but_rejects_expired_intermediate() {
        use rcgen::date_time_ymd;

        let signing_digest = [0x55u8; 32];
        let signing_hex = hex::encode(signing_digest);
        let cfg = test_config(true, "com.example.app", &signing_hex);
        let anchors = TrustAnchors {
            crl_last_synced_unix: Some(now_unix_secs()),
            ..Default::default()
        };
        let store = ChallengeStore::new();

        // Build an expired root CA (2016-05-26 .. 2026-05-24, mirroring factory Google RSA root).
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        root_params.not_before = date_time_ymd(2016, 5, 26);
        root_params.not_after = date_time_ymd(2026, 5, 24);
        let mut root_dn = DistinguishedName::new();
        root_dn.push(DnType::CommonName, "Legacy Factory Hardware Root CA");
        root_params.distinguished_name = root_dn;
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let (_, parsed_root) = parse_x509_certificate(root_cert.der()).unwrap();
        let pinned = vec![PinnedRootSpki {
            name: "Legacy Factory Hardware Root CA",
            spki_der: parsed_root.public_key().raw.to_vec(),
        }];

        // Case 1: Valid intermediate + valid leaf + expired pinned root -> ACCEPTED.
        let (ch1, _) = store.issue().unwrap();
        let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut inter_params = CertificateParams::default();
        inter_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        inter_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let mut inter_dn = DistinguishedName::new();
        inter_dn.push(DnType::CommonName, "Valid Intermediate");
        inter_params.distinguished_name = inter_dn;
        let inter_cert = inter_params
            .signed_by(&inter_key, &root_cert, &root_key)
            .unwrap();

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = CertificateParams::default();
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.custom_extensions.push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            build_key_description_der(
                2,
                &URL_SAFE_NO_PAD.decode(&ch1).unwrap(),
                &[0x11u8; 32],
                true,
                0,
                "com.example.app",
                &signing_digest,
            ),
        ));
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &inter_cert, &inter_key)
            .unwrap();

        let chain_ok = vec![
            STANDARD.encode(leaf_cert.der()),
            STANDARD.encode(inter_cert.der()),
            STANDARD.encode(root_cert.der()),
        ];
        assert!(
            verify_attestation_with_roots(&ch1, &chain_ok, &store, &anchors, &cfg, &pinned).is_ok()
        );

        // Case 2: Expired intermediate -> REJECTED.
        let (ch2, _) = store.issue().unwrap();
        let exp_inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut exp_inter_params = CertificateParams::default();
        exp_inter_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        exp_inter_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        exp_inter_params.not_before = date_time_ymd(2020, 1, 1);
        exp_inter_params.not_after = date_time_ymd(2025, 1, 1);
        let mut exp_inter_dn = DistinguishedName::new();
        exp_inter_dn.push(DnType::CommonName, "Expired Intermediate");
        exp_inter_params.distinguished_name = exp_inter_dn;
        let exp_inter_cert = exp_inter_params
            .signed_by(&exp_inter_key, &root_cert, &root_key)
            .unwrap();

        let mut leaf2_params = CertificateParams::default();
        leaf2_params.is_ca = IsCa::NoCa;
        leaf2_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf2_params.custom_extensions.push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            build_key_description_der(
                2,
                &URL_SAFE_NO_PAD.decode(&ch2).unwrap(),
                &[0x11u8; 32],
                true,
                0,
                "com.example.app",
                &signing_digest,
            ),
        ));
        let leaf2_cert = leaf2_params
            .signed_by(&leaf_key, &exp_inter_cert, &exp_inter_key)
            .unwrap();

        let chain_bad_inter = vec![
            STANDARD.encode(leaf2_cert.der()),
            STANDARD.encode(exp_inter_cert.der()),
            STANDARD.encode(root_cert.der()),
        ];
        assert!(matches!(
            verify_attestation_with_roots(&ch2, &chain_bad_inter, &store, &anchors, &cfg, &pinned),
            Err(AppError::Forbidden(_))
        ));
    }

    #[test]
    fn rejects_forged_leaf_signed_by_real_end_entity_keystore_leaf() {
        let signing_digest = [0xAAu8; 32];
        let signing_hex = hex::encode(signing_digest);
        let cfg = test_config(true, "com.example.app", &signing_hex);
        let anchors = TrustAnchors {
            crl_last_synced_unix: Some(now_unix_secs()),
            ..Default::default()
        };
        let store = ChallengeStore::new();

        // Root CA (unconstrained) -> Intermediate CA (unconstrained to specifically test BasicConstraints/KeyUsage on real_leaf)
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let mut root_dn = DistinguishedName::new();
        root_dn.push(DnType::CommonName, "Test Root CA");
        root_params.distinguished_name = root_dn;
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut inter_params = CertificateParams::default();
        inter_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        inter_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let mut inter_dn = DistinguishedName::new();
        inter_dn.push(DnType::CommonName, "Test Intermediate CA");
        inter_params.distinguished_name = inter_dn;
        let inter_cert = inter_params
            .signed_by(&inter_key, &root_cert, &root_key)
            .unwrap();

        // Attacker's real end-entity Keystore leaf cert (no BasicConstraints, DigitalSignature only).
        let real_leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut real_leaf_params = CertificateParams::default();
        real_leaf_params.is_ca = IsCa::NoCa;
        real_leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let mut real_leaf_dn = DistinguishedName::new();
        real_leaf_dn.push(DnType::CommonName, "Android Keystore Key");
        real_leaf_params.distinguished_name = real_leaf_dn;
        let real_leaf_cert = real_leaf_params
            .signed_by(&real_leaf_key, &inter_cert, &inter_key)
            .unwrap();

        // Attacker signs a forged leaf cert with real_leaf_key claiming StrongBox + Verified + target app!
        let (ch, _) = store.issue().unwrap();
        let forged_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut forged_params = CertificateParams::default();
        forged_params.is_ca = IsCa::NoCa;
        forged_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        forged_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                build_key_description_der(
                    2,
                    &URL_SAFE_NO_PAD.decode(&ch).unwrap(),
                    &[0x11u8; 32],
                    true,
                    0,
                    "com.example.app",
                    &signing_digest,
                ),
            ));
        let forged_leaf_cert = forged_params
            .signed_by(&forged_key, &real_leaf_cert, &real_leaf_key)
            .unwrap();

        let (_, parsed_root) = parse_x509_certificate(root_cert.der()).unwrap();
        let pinned = vec![PinnedRootSpki {
            name: "Test Root CA",
            spki_der: parsed_root.public_key().raw.to_vec(),
        }];

        let forged_chain = vec![
            STANDARD.encode(forged_leaf_cert.der()),
            STANDARD.encode(real_leaf_cert.der()),
            STANDARD.encode(inter_cert.der()),
            STANDARD.encode(root_cert.der()),
        ];

        assert!(matches!(
            verify_attestation_with_roots(&ch, &forged_chain, &store, &anchors, &cfg, &pinned),
            Err(AppError::Forbidden(_))
        ));
    }

    #[test]
    fn rejects_ca_without_key_cert_sign_and_pathlen_violation_and_ca_leaf() {
        let signing_digest = [0xBBu8; 32];
        let signing_hex = hex::encode(signing_digest);
        let cfg = test_config(true, "com.example.app", &signing_hex);
        let anchors = TrustAnchors {
            crl_last_synced_unix: Some(now_unix_secs()),
            ..Default::default()
        };
        let store = ChallengeStore::new();

        // Root CA
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let mut root_dn = DistinguishedName::new();
        root_dn.push(DnType::CommonName, "Test Root CA");
        root_params.distinguished_name = root_dn;
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let (_, parsed_root) = parse_x509_certificate(root_cert.der()).unwrap();
        let pinned = vec![PinnedRootSpki {
            name: "Test Root CA",
            spki_der: parsed_root.public_key().raw.to_vec(),
        }];

        // Case 1: Intermediate has CA:TRUE but lacks KeyUsage::KeyCertSign -> REJECTED.
        let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut inter_params = CertificateParams::default();
        inter_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        inter_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let mut inter_dn = DistinguishedName::new();
        inter_dn.push(DnType::CommonName, "No KeyCertSign CA");
        inter_params.distinguished_name = inter_dn;
        let inter_cert = inter_params
            .signed_by(&inter_key, &root_cert, &root_key)
            .unwrap();

        let (ch1, _) = store.issue().unwrap();
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = CertificateParams::default();
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.custom_extensions.push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            build_key_description_der(
                2,
                &URL_SAFE_NO_PAD.decode(&ch1).unwrap(),
                &[0x11u8; 32],
                true,
                0,
                "com.example.app",
                &signing_digest,
            ),
        ));
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &inter_cert, &inter_key)
            .unwrap();

        let chain_no_ku = vec![
            STANDARD.encode(leaf_cert.der()),
            STANDARD.encode(inter_cert.der()),
            STANDARD.encode(root_cert.der()),
        ];
        assert!(matches!(
            verify_attestation_with_roots(&ch1, &chain_no_ku, &store, &anchors, &cfg, &pinned),
            Err(AppError::Forbidden(_))
        ));

        // Case 2: Intermediate has pathLen=0 but signs another intermediate -> REJECTED.
        let inter_p0_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut inter_p0_params = CertificateParams::default();
        inter_p0_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        inter_p0_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let mut inter_p0_dn = DistinguishedName::new();
        inter_p0_dn.push(DnType::CommonName, "PathLen0 CA");
        inter_p0_params.distinguished_name = inter_p0_dn;
        let inter_p0_cert = inter_p0_params
            .signed_by(&inter_p0_key, &root_cert, &root_key)
            .unwrap();

        let sub_ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut sub_ca_params = CertificateParams::default();
        sub_ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        sub_ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let mut sub_ca_dn = DistinguishedName::new();
        sub_ca_dn.push(DnType::CommonName, "Sub CA");
        sub_ca_params.distinguished_name = sub_ca_dn;
        let sub_ca_cert = sub_ca_params
            .signed_by(&sub_ca_key, &inter_p0_cert, &inter_p0_key)
            .unwrap();

        let (ch2, _) = store.issue().unwrap();
        let mut leaf2_params = CertificateParams::default();
        leaf2_params.is_ca = IsCa::NoCa;
        leaf2_params.custom_extensions.push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            build_key_description_der(
                2,
                &URL_SAFE_NO_PAD.decode(&ch2).unwrap(),
                &[0x11u8; 32],
                true,
                0,
                "com.example.app",
                &signing_digest,
            ),
        ));
        let leaf2_cert = leaf2_params
            .signed_by(&leaf_key, &sub_ca_cert, &sub_ca_key)
            .unwrap();

        let chain_pathlen = vec![
            STANDARD.encode(leaf2_cert.der()),
            STANDARD.encode(sub_ca_cert.der()),
            STANDARD.encode(inter_p0_cert.der()),
            STANDARD.encode(root_cert.der()),
        ];
        assert!(matches!(
            verify_attestation_with_roots(&ch2, &chain_pathlen, &store, &anchors, &cfg, &pinned),
            Err(AppError::Forbidden(_))
        ));

        // Case 3: Leaf claims CA:TRUE -> REJECTED.
        let (ch3, _) = store.issue().unwrap();
        let mut ca_leaf_params = CertificateParams::default();
        ca_leaf_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_leaf_params.custom_extensions.push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            build_key_description_der(
                2,
                &URL_SAFE_NO_PAD.decode(&ch3).unwrap(),
                &[0x11u8; 32],
                true,
                0,
                "com.example.app",
                &signing_digest,
            ),
        ));
        let ca_leaf_cert = ca_leaf_params
            .signed_by(&leaf_key, &inter_p0_cert, &inter_p0_key)
            .unwrap();
        let chain_ca_leaf = vec![
            STANDARD.encode(ca_leaf_cert.der()),
            STANDARD.encode(inter_p0_cert.der()),
            STANDARD.encode(root_cert.der()),
        ];
        assert!(matches!(
            verify_attestation_with_roots(&ch3, &chain_ca_leaf, &store, &anchors, &cfg, &pinned),
            Err(AppError::Forbidden(_))
        ));
    }

    #[test]
    fn rejects_stale_crl_and_all_zero_verified_boot_key() {
        let signing_digest = [0xCCu8; 32];
        let signing_hex = hex::encode(signing_digest);
        let cfg = test_config(true, "com.example.app", &signing_hex);
        let store = ChallengeStore::new();

        // Stale CRL (>48h old) -> 503 ServiceUnavailable.
        let stale_anchors = TrustAnchors {
            crl_last_synced_unix: Some(1_700_000_000),
            ..Default::default()
        };
        let (ch1, _) = store.issue().unwrap();
        let ext1 = build_key_description_der(
            2,
            &URL_SAFE_NO_PAD.decode(&ch1).unwrap(),
            &[0x11u8; 32],
            true,
            0,
            "com.example.app",
            &signing_digest,
        );
        let (chain1, pinned1) = build_test_chain(ext1, 0x4001);
        assert!(matches!(
            verify_attestation_with_roots(&ch1, &chain1, &store, &stale_anchors, &cfg, &pinned1),
            Err(AppError::ServiceUnavailable(_))
        ));

        // All-zero verifiedBootKey even with Verified (0) -> 403 Forbidden.
        let fresh_anchors = TrustAnchors {
            crl_last_synced_unix: Some(now_unix_secs()),
            ..Default::default()
        };
        let (ch2, _) = store.issue().unwrap();
        let ext2 = build_key_description_der(
            2,
            &URL_SAFE_NO_PAD.decode(&ch2).unwrap(),
            &[0x00u8; 32],
            true,
            0,
            "com.example.app",
            &signing_digest,
        );
        let (chain2, pinned2) = build_test_chain(ext2, 0x4002);
        assert!(matches!(
            verify_attestation_with_roots(&ch2, &chain2, &store, &fresh_anchors, &cfg, &pinned2),
            Err(AppError::Forbidden(_))
        ));
    }
}
