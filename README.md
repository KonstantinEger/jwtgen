# JWTgen

Generator for JWTs and signing them with JWKs.

## Usage

```
<stream jwk> | jwkgen --iss <issuer> --aud <audience> [OPTIONS]

jwkgen -k <jwk-file> --iss <issuer> --aud <audience> [OPTIONS]
```

See more with `jwkgen --help`

### Options

- `-k | --jwkfile`: path to the JWK file. Can also be read from STDIN. Either path to a file or piping in is required.
- `--aud`: value for the `aud` claim. required.
- `--iss`: value for the `iss` claim. required.
- `--ttl`: time to live. sets the `exp` claim accordingly. default: "1min". required.
- `--alg`: signing algorithm. default: "rs256". required.
- `-c | --claim`: add claims to the payload. example: `-c foo=bar -c baz=boom`

## Installation

**Prerequisites**: Rust toolchain with cargo.

```sh
# clone repository
git clone https://github.com/KonstantinEger/jwtgen.git
# install
cargo install --path ./jwtgen
```
