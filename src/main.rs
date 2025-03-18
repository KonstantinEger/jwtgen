pub mod args;

use args::{Alg, Args};
use clap::Parser;
use josekit::{
    jwk::Jwk,
    jws::{
        alg::{
            ecdsa::EcdsaJwsAlgorithm, eddsa::EddsaJwsAlgorithm, rsassa::RsassaJwsAlgorithm,
            rsassa_pss::RsassaPssJwsAlgorithm,
        },
        JwsHeader, JwsSigner,
    },
    jwt::JwtPayload,
};
use std::time::SystemTime;

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let jwk = read_jwk(&args)?;

    let header = build_header(&args, &jwk);
    let payload = build_payload(&args)?;

    let signer: Box<dyn JwsSigner> = match args.alg {
        Alg::RS256 => Box::new(RsassaJwsAlgorithm::Rs256.signer_from_jwk(&jwk)?),
        Alg::RS384 => Box::new(RsassaJwsAlgorithm::Rs384.signer_from_jwk(&jwk)?),
        Alg::RS512 => Box::new(RsassaJwsAlgorithm::Rs512.signer_from_jwk(&jwk)?),
        Alg::PS265 => Box::new(RsassaPssJwsAlgorithm::Ps256.signer_from_jwk(&jwk)?),
        Alg::PS384 => Box::new(RsassaPssJwsAlgorithm::Ps384.signer_from_jwk(&jwk)?),
        Alg::PS512 => Box::new(RsassaPssJwsAlgorithm::Ps512.signer_from_jwk(&jwk)?),
        Alg::ES256 => Box::new(EcdsaJwsAlgorithm::Es256.signer_from_jwk(&jwk)?),
        Alg::ES256K => Box::new(EcdsaJwsAlgorithm::Es256k.signer_from_jwk(&jwk)?),
        Alg::ES384 => Box::new(EcdsaJwsAlgorithm::Es384.signer_from_jwk(&jwk)?),
        Alg::ES512 => Box::new(EcdsaJwsAlgorithm::Es512.signer_from_jwk(&jwk)?),
        Alg::EDDSA => Box::new(EddsaJwsAlgorithm::Eddsa.signer_from_jwk(&jwk)?),
    };
    let jwt = josekit::jwt::encode_with_signer(&payload, &header, signer.as_ref())?;

    println!("{jwt}");
    Ok(())
}
/// Read JWK from file (or stdin).
fn read_jwk(args: &Args) -> anyhow::Result<Jwk> {
    if let Some(path) = &args.jwkfile {
        let mut file = std::fs::File::open(path)?;
        Ok(Jwk::from_reader(&mut file)?)
    } else {
        let mut stdin = std::io::stdin();
        Ok(Jwk::from_reader(&mut stdin)?)
    }
}

fn build_header(args: &Args, jwk: &Jwk) -> JwsHeader {
    let mut header = JwsHeader::new();
    header.set_algorithm(format!("{:?}", args.alg));
    if let Some(kid) = jwk.key_id() {
        header.set_key_id(kid);
    }
    header
}

fn build_payload(args: &Args) -> anyhow::Result<JwtPayload> {
    let mut payload = JwtPayload::new();
    payload.set_issuer(&args.iss);
    payload.set_audience(vec![&args.aud]);
    let exp = SystemTime::now() + args.ttl;
    payload.set_expires_at(&exp);

    for (key, value) in &args.additional_claims {
        payload.set_claim(key, Some(value.as_str().into()))?;
    }

    Ok(payload)
}
