# keycloak-spi-x509cert-rfc9440

[![Build Status of Main](https://img.shields.io/github/check-runs/seiferma/keycloak-spi-x509cert-rfc9440/main)](https://github.com/seiferma/keycloak-spi-x509cert-rfc9440/actions?query=branch%3Amain++)
[![Latest Release](https://img.shields.io/github/v/release/seiferma/keycloak-spi-x509cert-rfc9440)](https://github.com/seiferma/keycloak-spi-x509cert-rfc9440/releases/latest)
[![License](https://img.shields.io/github/license/seiferma/keycloak-spi-x509cert-rfc9440)](https://github.com/seiferma/keycloak-spi-x509cert-rfc9440/blob/main/LICENSE)

This repository hosts an implementation of the X509 client certificate lookup for Keyloak in combination with a
RFC 9440 compliant reverse proxy.

## How to use

The following steps exemplify on how to use the provider with a caddy reverse proxy.
Caddy does not provide the client certificate chain, so these steps are omitted.
If you need the certificate chain, either let caddy validate the certificate or
add the intermediate certificates to the keycloak trust store.

1. Read the [official manual](https://www.keycloak.org/server/reverseproxy#_enabling_client_certificate_lookup)
   (this manual only covers the caddy-specific aspects)
1. Build the jar by running `./gradlew build`
1. Copy the jar (`build/libs/*.jar`) into the `providers` folder of keycloak
1. Configure keycloak
    * `--spi-x509cert-lookup-provider=rfc9440`
    * `--spi-x509cert-lookup-rfc9440-certificate-chain-length=0`
1. Configure Caddy
```
keycloak.example.org {
        tls {
                client_auth {
                        mode request
                }
        }
        vars cert_header ""
        @certavailable vars_regexp {tls_client_certificate_der_base64} .+
        vars @certavailable cert_header ":{tls_client_certificate_der_base64}:"
        reverse_proxy https://keycloak:8443 {
                header_up Client-Cert {vars.cert_header}
        }
}
```

## Background

This addresses an [open issue](https://github.com/keycloak/keycloak/issues/20761) in the keycloak repository
that is about supporting [RFC 9440](https://datatracker.ietf.org/doc/rfc9440/). The implementation enables using Caddy.