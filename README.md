# weir-ce

The open-source **Community Edition** core for web-security tooling, in Rust — the reusable,
tool-agnostic building blocks, published from a private monorepo. It is a **derived projection**:
do not hand-edit; changes are made upstream and re-exported.

## Crates

- **`http-model`** — transport-level HTTP/WebSocket DTOs (raw, un-normalized request/response/frame
  types). No dependencies beyond `serde`.
- **`proxy-core`** — a MITM intercepting-proxy engine: on-the-fly TLS via a local root CA, HTTP/1.1
  + HTTP/2 (incl. a single-packet path), WebSocket tunneling, byte-exact raw-send (desync), upstream
  proxy chaining (HTTP CONNECT / SOCKS5), and match & replace. `#![forbid(unsafe_code)]`,
  loopback-only, typed errors.

## ⚠️ Authorized use only

`proxy-core` is a **MITM** engine: it intercepts and decrypts HTTPS by minting certificates from its
own root CA. Use it **only** against targets you are allowed to test — your own systems, labs/CTF, or
bug bounty within program scope. The root CA private key never needs to leave the machine.

## Build / test

```sh
cargo build
cargo test --workspace
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

## License

[MIT](./LICENSE) © 2026 rudolfowski.
