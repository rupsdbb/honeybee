use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use miniscript::bitcoin::Network;

#[derive(Parser, Debug)]
#[command(name = "honeybee", version, about = "Self-hosted, watch-only Bitcoin wallet for electrs")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub config: Config,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the web server (default)
    Serve,
    /// Read a password from stdin and print a hash for HONEYBEE_PASSWORD_HASH
    HashPassword,
}

#[derive(Args, Debug, Clone)]
pub struct Config {
    /// Electrum server, as tcp://host:port or ssl://host:port
    #[arg(long, env = "HONEYBEE_ELECTRUM", default_value = "tcp://127.0.0.1:50001")]
    pub electrum: String,

    /// PEM file with an extra CA (or the server's self-signed certificate) to trust for ssl://
    #[arg(long, env = "HONEYBEE_ELECTRUM_CA_FILE")]
    pub electrum_ca_file: Option<PathBuf>,

    /// Skip TLS certificate verification for ssl:// (only for a server on a network you trust)
    #[arg(long, env = "HONEYBEE_ELECTRUM_INSECURE")]
    pub electrum_insecure: bool,

    /// Bitcoin network: bitcoin (mainnet), testnet, testnet4, signet or regtest
    #[arg(long, env = "HONEYBEE_NETWORK", default_value = "bitcoin", value_parser = parse_network)]
    pub network: Network,

    /// Address and port for the web interface
    #[arg(long, env = "HONEYBEE_LISTEN", default_value = "127.0.0.1:8585")]
    pub listen: SocketAddr,

    /// Directory for the SQLite database
    #[arg(long, env = "HONEYBEE_DATA_DIR", default_value = "./data")]
    pub data_dir: PathBuf,

    /// Password hash from `honeybee hash-password` (preferred over HONEYBEE_PASSWORD)
    #[arg(long, env = "HONEYBEE_PASSWORD_HASH", hide_env_values = true)]
    pub password_hash: Option<String>,

    /// Plain-text login password
    #[arg(long, env = "HONEYBEE_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,

    /// Allow running without a password on a non-loopback address (e.g. behind an authenticating proxy)
    #[arg(long, env = "HONEYBEE_NO_AUTH")]
    pub no_auth: bool,

    /// Mark the session cookie Secure (set when served over HTTPS)
    #[arg(long, env = "HONEYBEE_SECURE_COOKIE")]
    pub secure_cookie: bool,

    /// Default gap limit for new wallets
    #[arg(long, env = "HONEYBEE_GAP_LIMIT", default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub gap_limit: u32,

    /// Block explorer base URL for transaction links, e.g. http://mempool.local (no links when unset)
    #[arg(long, env = "HONEYBEE_EXPLORER_URL")]
    pub explorer_url: Option<String>,
}

fn parse_network(s: &str) -> Result<Network, String> {
    match s.to_ascii_lowercase().as_str() {
        "bitcoin" | "mainnet" | "main" => Ok(Network::Bitcoin),
        "testnet" | "testnet3" | "test" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(format!("unknown network '{other}'")),
    }
}

/// Genesis block hash the Electrum server must report for the configured network.
/// Custom signets have their own genesis, so signet is not checked.
pub fn expected_genesis(network: Network) -> Option<&'static str> {
    match network {
        Network::Bitcoin => Some("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
        Network::Testnet => Some("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"),
        Network::Testnet4 => Some("00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"),
        Network::Regtest => Some("0f9188f13cb7b2c71f2a335e5a4fc328bf5beb436012afca590b1a11466e2206"),
        _ => None,
    }
}
