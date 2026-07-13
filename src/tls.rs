pub fn ensure_crypto_provider() {
    let _installation = rustls::crypto::ring::default_provider().install_default();
}
