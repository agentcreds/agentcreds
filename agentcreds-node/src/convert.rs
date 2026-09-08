use agentcreds_core::did::{CheqdNetwork, KeyAlgorithm};
use agentcreds_core::registry::TrustLevel;

use crate::error::invalid_arg;

pub fn parse_algorithm(algorithm: Option<&str>) -> napi::Result<Option<KeyAlgorithm>> {
    match algorithm {
        None => Ok(None),
        Some(a) => match a.to_ascii_lowercase().as_str() {
            "ed25519" => Ok(Some(KeyAlgorithm::Ed25519)),
            "p256" | "p-256" | "secp256r1" => Ok(Some(KeyAlgorithm::P256)),
            other => Err(invalid_arg(format!(
                "unknown key algorithm '{other}' (expected 'ed25519' or 'p256')"
            ))),
        },
    }
}

pub fn algorithm_to_str(algorithm: KeyAlgorithm) -> &'static str {
    match algorithm {
        KeyAlgorithm::Ed25519 => "ed25519",
        KeyAlgorithm::P256 => "p256",
    }
}

pub fn parse_cheqd_network(network: &str) -> napi::Result<CheqdNetwork> {
    match network.to_ascii_lowercase().as_str() {
        "mainnet" => Ok(CheqdNetwork::Mainnet),
        "testnet" => Ok(CheqdNetwork::Testnet),
        other => Err(invalid_arg(format!(
            "unknown cheqd network '{other}' (expected 'mainnet' or 'testnet')"
        ))),
    }
}

pub fn parse_trust_level(level: &str) -> napi::Result<TrustLevel> {
    match level.to_ascii_lowercase().as_str() {
        "unverified" => Ok(TrustLevel::Unverified),
        "self_asserted" | "self-asserted" => Ok(TrustLevel::SelfAsserted),
        "verified" => Ok(TrustLevel::Verified),
        "authoritative" => Ok(TrustLevel::Authoritative),
        other => Err(invalid_arg(format!(
            "unknown trust level '{other}' (expected 'unverified', 'self_asserted', 'verified', or 'authoritative')"
        ))),
    }
}

pub fn trust_level_to_str(level: TrustLevel) -> &'static str {
    match level {
        TrustLevel::Unverified => "unverified",
        TrustLevel::SelfAsserted => "self_asserted",
        TrustLevel::Verified => "verified",
        TrustLevel::Authoritative => "authoritative",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_algorithm_handles_aliases_and_default() {
        assert_eq!(parse_algorithm(None).unwrap(), None);
        assert_eq!(
            parse_algorithm(Some("ed25519")).unwrap(),
            Some(KeyAlgorithm::Ed25519)
        );
        assert_eq!(
            parse_algorithm(Some("Ed25519")).unwrap(),
            Some(KeyAlgorithm::Ed25519)
        );
        assert_eq!(
            parse_algorithm(Some("p256")).unwrap(),
            Some(KeyAlgorithm::P256)
        );
        assert_eq!(
            parse_algorithm(Some("p-256")).unwrap(),
            Some(KeyAlgorithm::P256)
        );
        assert_eq!(
            parse_algorithm(Some("secp256r1")).unwrap(),
            Some(KeyAlgorithm::P256)
        );
        assert!(parse_algorithm(Some("rsa")).is_err());
    }

    #[test]
    fn algorithm_to_str_round_trips() {
        assert_eq!(algorithm_to_str(KeyAlgorithm::Ed25519), "ed25519");
        assert_eq!(algorithm_to_str(KeyAlgorithm::P256), "p256");
        assert_eq!(
            parse_algorithm(Some(algorithm_to_str(KeyAlgorithm::Ed25519))).unwrap(),
            Some(KeyAlgorithm::Ed25519)
        );
    }

    #[test]
    fn parse_cheqd_network_handles_known_and_unknown() {
        assert_eq!(
            parse_cheqd_network("mainnet").unwrap(),
            CheqdNetwork::Mainnet
        );
        assert_eq!(
            parse_cheqd_network("MAINNET").unwrap(),
            CheqdNetwork::Mainnet
        );
        assert_eq!(
            parse_cheqd_network("testnet").unwrap(),
            CheqdNetwork::Testnet
        );
        assert!(parse_cheqd_network("devnet").is_err());
    }

    #[test]
    fn trust_level_round_trips_through_strings() {
        let levels = [
            TrustLevel::Unverified,
            TrustLevel::SelfAsserted,
            TrustLevel::Verified,
            TrustLevel::Authoritative,
        ];
        for level in levels {
            let s = trust_level_to_str(level);
            assert_eq!(parse_trust_level(s).unwrap(), level);
        }
        assert_eq!(
            parse_trust_level("self-asserted").unwrap(),
            TrustLevel::SelfAsserted
        );
        assert!(parse_trust_level("super-trusted").is_err());
    }
}
