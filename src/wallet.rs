//! Turning user input (an extended public key, output descriptors or a list
//! of addresses) into scripts to watch.

use std::str::FromStr;

use miniscript::bitcoin::bip32::Xpub;
use miniscript::bitcoin::secp256k1::Secp256k1;
use miniscript::bitcoin::{Address, Network, NetworkKind, ScriptBuf, base58};
use miniscript::{Descriptor, DescriptorPublicKey, ForEachKey};
use serde::{Deserialize, Serialize};

/// What a wallet watches. Stored as JSON in the database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WalletSpec {
    /// Single-path descriptors for the receive chain and (optionally) the change chain.
    Descriptor { receive: String, change: Option<String> },
    /// A fixed set of addresses.
    Addresses { addresses: Vec<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptType {
    /// Legacy P2PKH (BIP44)
    Pkh,
    /// Nested segwit P2SH-P2WPKH (BIP49)
    ShWpkh,
    /// Native segwit P2WPKH (BIP84)
    Wpkh,
    /// Taproot single key (BIP86)
    Tr,
}

impl ScriptType {
    fn wrap(self, key: &str) -> String {
        match self {
            ScriptType::Pkh => format!("pkh({key})"),
            ScriptType::ShWpkh => format!("sh(wpkh({key}))"),
            ScriptType::Wpkh => format!("wpkh({key})"),
            ScriptType::Tr => format!("tr({key})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ChainKind {
    Receive,
    Change,
    Imported,
}

/// A source of scripts: a ranged descriptor or a fixed list.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // at most two per wallet
pub enum Chain {
    Ranged { kind: ChainKind, descriptor: Descriptor<DescriptorPublicKey> },
    Fixed { kind: ChainKind, scripts: Vec<ScriptBuf> },
}

impl Chain {
    pub fn kind(&self) -> ChainKind {
        match self {
            Chain::Ranged { kind, .. } | Chain::Fixed { kind, .. } => *kind,
        }
    }
}

pub fn script_at(descriptor: &Descriptor<DescriptorPublicKey>, index: u32) -> Result<ScriptBuf, String> {
    descriptor
        .at_derivation_index(index)
        .map(|d| d.script_pubkey())
        .map_err(|e| format!("cannot derive index {index}: {e}"))
}

pub fn address_of(script: &ScriptBuf, network: Network) -> Option<String> {
    Address::from_script(script, network).ok().map(|a| a.to_string())
}

impl WalletSpec {
    /// The script chains to scan for this wallet.
    pub fn chains(&self, network: Network) -> Result<Vec<Chain>, String> {
        match self {
            WalletSpec::Descriptor { receive, change } => {
                let mut chains = Vec::new();
                for (kind, text) in [(ChainKind::Receive, Some(receive)), (ChainKind::Change, change.as_ref())] {
                    let Some(text) = text else { continue };
                    let descriptor = parse_public_descriptor(text, network)?;
                    if descriptor.has_wildcard() {
                        chains.push(Chain::Ranged { kind, descriptor });
                    } else {
                        let script = script_at(&descriptor, 0)?;
                        let kind = if kind == ChainKind::Receive { ChainKind::Imported } else { kind };
                        chains.push(Chain::Fixed { kind, scripts: vec![script] });
                    }
                }
                Ok(chains)
            }
            WalletSpec::Addresses { addresses } => {
                let scripts = addresses
                    .iter()
                    .map(|a| parse_address(a, network).map(|a| a.script_pubkey()))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(vec![Chain::Fixed { kind: ChainKind::Imported, scripts }])
            }
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            WalletSpec::Descriptor { .. } => "descriptor",
            WalletSpec::Addresses { .. } => "addresses",
        }
    }
}

/// Parse what the user pasted into the "add wallet" form.
///
/// `script_type` is only needed for an `xpub`/`tpub`, whose version bytes
/// don't say how it is used. `ypub`/`zpub` & co. imply it.
pub fn parse_input(input: &str, script_type: Option<ScriptType>, network: Network) -> Result<WalletSpec, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Enter an xpub, a descriptor or some addresses.".into());
    }
    reject_secrets(input)?;

    if input.contains('(') {
        let lines: Vec<&str> = input.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        return match lines.as_slice() {
            [one] => from_single_descriptor(one, network),
            [receive, change] => {
                let r = parse_public_descriptor(receive, network)?;
                let c = parse_public_descriptor(change, network)?;
                if r.is_multipath() || c.is_multipath() {
                    return Err("Give either one multipath descriptor (<0;1>) or two single-path ones.".into());
                }
                Ok(WalletSpec::Descriptor { receive: r.to_string(), change: Some(c.to_string()) })
            }
            _ => Err("Expected one descriptor, or two (receive and change) on separate lines.".into()),
        };
    }

    let tokens: Vec<&str> =
        input.split(|c: char| c.is_whitespace() || c == ',' || c == ';').filter(|t| !t.is_empty()).collect();

    if tokens.len() == 1 && looks_like_extended_key(tokens[0]) {
        return from_extended_key(tokens[0], script_type, network);
    }

    let mut addresses = Vec::new();
    for token in tokens {
        let addr = parse_address(token, network)?.to_string();
        if !addresses.contains(&addr) {
            addresses.push(addr);
        }
    }
    if addresses.len() > 5000 {
        return Err("At most 5000 addresses per wallet.".into());
    }
    Ok(WalletSpec::Addresses { addresses })
}

fn reject_secrets(input: &str) -> Result<(), String> {
    const PRIVATE_PREFIXES: [&str; 10] =
        ["xprv", "yprv", "zprv", "Yprv", "Zprv", "tprv", "uprv", "vprv", "Uprv", "Vprv"];
    if PRIVATE_PREFIXES.iter().any(|p| input.contains(p)) {
        return Err("That is a PRIVATE key. Honeybee is watch-only: use the matching xpub/zpub instead. \
                    Consider the key exposed if you pasted it anywhere untrusted."
            .into());
    }
    let words: Vec<&str> = input.split_whitespace().collect();
    if [12, 15, 18, 21, 24].contains(&words.len()) && words.iter().all(|w| w.chars().all(|c| c.is_ascii_lowercase())) {
        return Err("That looks like a seed phrase. Never enter it here: Honeybee only needs an xpub, \
                    descriptor or addresses."
            .into());
    }
    Ok(())
}

fn parse_address(s: &str, network: Network) -> Result<Address, String> {
    let unchecked = Address::from_str(s).map_err(|e| format!("'{s}' is not a valid address: {e}"))?;
    unchecked.require_network(network).map_err(|_| format!("'{s}' is not an address for {network}"))
}

fn parse_public_descriptor(s: &str, network: Network) -> Result<Descriptor<DescriptorPublicKey>, String> {
    let descriptor = match Descriptor::<DescriptorPublicKey>::from_str(s) {
        Ok(d) => d,
        Err(e) => {
            // Give a clear message if it only failed because it has private keys.
            if Descriptor::parse_descriptor(&Secp256k1::new(), s).is_ok() {
                return Err("That descriptor contains PRIVATE keys. Honeybee is watch-only: \
                            export the public descriptor instead."
                    .into());
            }
            return Err(format!("Invalid descriptor: {e}"));
        }
    };
    let want = NetworkKind::from(network);
    let wrong_network = descriptor.for_any_key(|key| {
        let kind = match key {
            DescriptorPublicKey::XPub(x) => Some(x.xkey.network),
            DescriptorPublicKey::MultiXPub(x) => Some(x.xkey.network),
            DescriptorPublicKey::Single(_) => None,
        };
        kind.is_some_and(|k| k != want)
    });
    if wrong_network {
        return Err(format!("The descriptor's keys are not for {network}."));
    }
    Ok(descriptor)
}

fn from_single_descriptor(s: &str, network: Network) -> Result<WalletSpec, String> {
    let descriptor = parse_public_descriptor(s, network)?;
    if descriptor.is_multipath() {
        let mut singles = descriptor.into_single_descriptors().map_err(|e| e.to_string())?;
        if singles.len() != 2 {
            return Err("Multipath descriptors must have exactly two paths, like <0;1>.".into());
        }
        let change = singles.pop().map(|d| d.to_string());
        let receive = singles.pop().expect("two paths").to_string();
        return Ok(WalletSpec::Descriptor { receive, change });
    }
    // A lone ".../0/*" descriptor: watch the matching ".../1/*" change chain too,
    // as most wallets would.
    let body = s.split('#').next().unwrap_or(s);
    let change = if descriptor.has_wildcard() && body.contains("/0/*") && !body.contains("/1/*") {
        parse_public_descriptor(&body.replace("/0/*", "/1/*"), network).ok().map(|d| d.to_string())
    } else {
        None
    };
    Ok(WalletSpec::Descriptor { receive: descriptor.to_string(), change })
}

fn looks_like_extended_key(token: &str) -> bool {
    let key = token.rsplit(']').next().unwrap_or(token);
    key.len() > 100
        && ["xpub", "ypub", "zpub", "Ypub", "Zpub", "tpub", "upub", "vpub", "Upub", "Vpub"]
            .iter()
            .any(|p| key.starts_with(p))
}

/// SLIP-132 version bytes -> (mainnet?, implied script type, multisig?)
fn slip132(version: [u8; 4]) -> Option<(bool, Option<ScriptType>, bool)> {
    Some(match version {
        [0x04, 0x88, 0xb2, 0x1e] => (true, None, false), // xpub
        [0x04, 0x9d, 0x7c, 0xb2] => (true, Some(ScriptType::ShWpkh), false), // ypub
        [0x04, 0xb2, 0x47, 0x46] => (true, Some(ScriptType::Wpkh), false), // zpub
        [0x02, 0x95, 0xb4, 0x3f] | [0x02, 0xaa, 0x7e, 0xd3] => (true, None, true), // Ypub, Zpub
        [0x04, 0x35, 0x87, 0xcf] => (false, None, false), // tpub
        [0x04, 0x4a, 0x52, 0x62] => (false, Some(ScriptType::ShWpkh), false), // upub
        [0x04, 0x5f, 0x1c, 0xf6] => (false, Some(ScriptType::Wpkh), false), // vpub
        [0x02, 0x42, 0x89, 0xef] | [0x02, 0x57, 0x54, 0x83] => (false, None, true), // Upub, Vpub
        _ => return None,
    })
}

fn from_extended_key(token: &str, script_type: Option<ScriptType>, network: Network) -> Result<WalletSpec, String> {
    let (origin, key) = match token.rfind(']') {
        Some(i) => (&token[..=i], &token[i + 1..]),
        None => ("", token),
    };
    if !origin.is_empty() && !origin.starts_with('[') {
        return Err("Malformed key origin; expected [fingerprint/path]xpub...".into());
    }
    let mut data = base58::decode_check(key).map_err(|e| format!("Invalid extended key: {e}"))?;
    if data.len() != 78 {
        return Err("Invalid extended key length.".into());
    }
    let version: [u8; 4] = data[..4].try_into().expect("4 bytes");
    let (mainnet, implied, multisig) = slip132(version).ok_or("Unknown extended key version.")?;
    if multisig {
        return Err("Ypub/Zpub/Upub/Vpub are multisig cosigner keys; add the wallet's full descriptor instead, \
                    e.g. wsh(sortedmulti(2,[...]xpub1/<0;1>/*,[...]xpub2/<0;1>/*,...))."
            .into());
    }
    if mainnet != (network == Network::Bitcoin) {
        return Err(format!("This key is not for {network}."));
    }
    let script_type = match (implied, script_type) {
        (Some(implied), Some(chosen)) if implied != chosen => {
            return Err(format!(
                "This key's prefix implies {implied:?} but {chosen:?} was selected; pick \"Auto\" or the matching type."
            ));
        }
        (Some(t), _) | (None, Some(t)) => t,
        (None, None) => {
            return Err(
                "An xpub/tpub doesn't record its script type. Choose one (native segwit for most modern wallets)."
                    .into(),
            );
        }
    };
    data[..4].copy_from_slice(if mainnet { &[0x04, 0x88, 0xb2, 0x1e] } else { &[0x04, 0x35, 0x87, 0xcf] });
    let xpub = Xpub::decode(&data).map_err(|e| format!("Invalid extended key: {e}"))?;
    from_single_descriptor(&script_type.wrap(&format!("{origin}{xpub}/<0;1>/*")), network)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Account keys for the BIP test mnemonic "abandon abandon ... about".
    const BIP44_XPUB: &str = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj";
    const BIP49_YPUB: &str = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP";
    const BIP84_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
    const BIP86_XPUB: &str = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";

    fn addr(spec: &WalletSpec, kind: ChainKind, index: u32) -> String {
        let chains = spec.chains(Network::Bitcoin).unwrap();
        let chain = chains.iter().find(|c| c.kind() == kind).unwrap();
        match chain {
            Chain::Ranged { descriptor, .. } => {
                address_of(&script_at(descriptor, index).unwrap(), Network::Bitcoin).unwrap()
            }
            Chain::Fixed { scripts, .. } => address_of(&scripts[index as usize], Network::Bitcoin).unwrap(),
        }
    }

    #[test]
    fn bip84_zpub() {
        let spec = parse_input(BIP84_ZPUB, None, Network::Bitcoin).unwrap();
        assert_eq!(addr(&spec, ChainKind::Receive, 0), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(addr(&spec, ChainKind::Receive, 1), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
        assert_eq!(addr(&spec, ChainKind::Change, 0), "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
    }

    #[test]
    fn bip49_ypub() {
        let spec = parse_input(BIP49_YPUB, None, Network::Bitcoin).unwrap();
        assert_eq!(addr(&spec, ChainKind::Receive, 0), "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf");
        assert_eq!(addr(&spec, ChainKind::Change, 0), "34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7");
    }

    #[test]
    fn bip44_xpub_needs_script_type() {
        assert!(parse_input(BIP44_XPUB, None, Network::Bitcoin).is_err());
        let spec = parse_input(BIP44_XPUB, Some(ScriptType::Pkh), Network::Bitcoin).unwrap();
        assert_eq!(addr(&spec, ChainKind::Receive, 0), "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
        assert_eq!(addr(&spec, ChainKind::Change, 0), "1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH");
    }

    #[test]
    fn bip86_taproot() {
        let spec = parse_input(BIP86_XPUB, Some(ScriptType::Tr), Network::Bitcoin).unwrap();
        assert_eq!(
            addr(&spec, ChainKind::Receive, 0),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert_eq!(addr(&spec, ChainKind::Change, 0), "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7");
    }

    #[test]
    fn conflicting_script_type_rejected() {
        assert!(parse_input(BIP84_ZPUB, Some(ScriptType::Tr), Network::Bitcoin).is_err());
    }

    #[test]
    fn descriptor_with_origin_and_checksum() {
        let s = "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#afwvtk2s";
        let spec = parse_input(s, None, Network::Bitcoin).unwrap();
        assert_eq!(addr(&spec, ChainKind::Receive, 0), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        // the /1/* change chain is inferred
        assert_eq!(addr(&spec, ChainKind::Change, 0), "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
    }

    #[test]
    fn bad_checksum_rejected() {
        let s = "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#afwvtk2q";
        assert!(parse_input(s, None, Network::Bitcoin).is_err());
    }

    #[test]
    fn multisig_descriptor() {
        let x = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
        let s = format!("wsh(sortedmulti(1,{x}/<0;1>/*,{BIP86_XPUB}/<0;1>/*))");
        let spec = parse_input(&s, None, Network::Bitcoin).unwrap();
        assert!(addr(&spec, ChainKind::Receive, 0).starts_with("bc1q"));
        assert_eq!(addr(&spec, ChainKind::Receive, 0).len(), 62);
    }

    #[test]
    fn addresses() {
        let spec = parse_input(
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu, 1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA\n1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
            None,
            Network::Bitcoin,
        )
        .unwrap();
        match spec {
            WalletSpec::Addresses { addresses } => assert_eq!(addresses.len(), 2),
            _ => panic!(),
        }
        assert!(parse_input("tb1qcr8te4kr609gcawutmrza0j4xv80jy8z39pg9d", None, Network::Bitcoin).is_err());
    }

    #[test]
    fn secrets_rejected() {
        let seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(parse_input(seed, None, Network::Bitcoin).unwrap_err().contains("seed phrase"));
        let xprv = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";
        assert!(parse_input(xprv, None, Network::Bitcoin).unwrap_err().contains("PRIVATE"));
        let wif = "wpkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)";
        assert!(parse_input(wif, None, Network::Bitcoin).unwrap_err().contains("PRIVATE"));
    }

    #[test]
    fn wrong_network_rejected() {
        assert!(parse_input(BIP84_ZPUB, None, Network::Testnet).is_err());
    }
}
