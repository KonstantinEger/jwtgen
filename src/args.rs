use std::{path::PathBuf, time::Duration};

use clap::{Parser, ValueEnum};

/// Generate signed JWTs using JWKs.
#[derive(Parser, Debug)]
pub struct Args {
    /// Path to JWK file. If not present, use stdin.
    #[arg(long, short = 'k')]
    pub jwkfile: Option<PathBuf>,

    /// Issuer claim (iss)
    #[arg(long)]
    pub iss: String,

    /// Audience claim (aud)
    #[arg(long)]
    pub aud: String,

    /// Time to live, sets expiry (exp) accordingly.
    #[arg(long)]
    #[clap(value_parser = humantime::parse_duration, default_value = "1min")]
    pub ttl: Duration,

    #[arg(long, value_enum)]
    #[clap(default_value = "rs256")]
    pub alg: Alg,

    /// Add more claims to the payload.
    #[arg(short = 'c', long = "claim", value_parser = parse_key_value)]
    pub additional_claims: Vec<(String, String)>,
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

fn parse_key_value(src: &str) -> anyhow::Result<(String, String)> {
    src.split_once('=')
        .ok_or_else(|| anyhow::anyhow!("invalid KEY=VALUE: no '=' found in {src}"))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
}
