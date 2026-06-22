use std::time::Duration;
use std::str::FromStr;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

/// Generate signed JWTs using JWKs.
#[derive(Parser, Debug)]
pub struct Args {
    /// Path to JWK file. If not present, use stdin.
    #[arg(long, short = 'k')]
    pub jwkfile: Option<PathBuf>,

    /// Issuer claim (iss).
    #[arg(long)]
    pub iss: Option<String>,

    /// Audience claim (aud), can be used multiple times.
    #[arg(long)]
    pub aud: Vec<String>,

    /// Time to live, sets expiry (exp) accordingly.
    #[arg(long)]
    #[clap(value_parser = humantime::parse_duration, default_value = "1min")]
    pub ttl: Duration,

    #[arg(long, value_enum)]
    #[clap(default_value = "rs256")]
    pub alg: Alg,

    /// Add more claims to the payload.
    #[arg(short = 'c', long = "claim", value_parser = parse_key_value)]
    pub additional_claims: Vec<(String, josekit::Value)>,
}

#[derive(Debug, ValueEnum, Clone, Copy)]
pub enum Alg {
    // TODO: support more algorithms
    RS256,
    RS384,
    RS512,
    PS265,
    PS384,
    PS512,
    ES256,
    ES256K,
    ES384,
    ES512,
    EDDSA,
}

fn parse_key_value(src: &str) -> anyhow::Result<(String, josekit::Value)> {
    src.split_once('=')
        .ok_or_else(|| anyhow::anyhow!("invalid KEY=VALUE: no '=' found in {src}"))
        .and_then(|(key, value)| {
            Ok((key.to_owned(), josekit::Value::from_str(value)?))
        })
}
