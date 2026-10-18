#!/usr/bin/env bash
# ci/network-tls-identity.sh: a new test identity for NetworkTLSTests
# (Tests/VegaTests/NetworkTLSTests.swift), printed as the base64 blocks the
# test embeds. Apple refuses a TLS certificate valid for more than 825 days,
# even as an anchor, so the identity runs out and is renewed with this:
# paste the two blocks and the new expiry date into the test.
#
# A self-signed P-256 certificate for "localhost" and 127.0.0.1, valid for
# 820 days, and its key as PKCS #12 with passphrase "vega", in 3DES and
# SHA-1, which every Apple OS imports. Needs OpenSSL 3 or later.
set -eu
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$dir/key.pem" -out "$dir/cert.pem" -days 820 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "extendedKeyUsage=serverAuth,clientAuth" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign" 2>/dev/null
openssl pkcs12 -export -inkey "$dir/key.pem" -in "$dir/cert.pem" -out "$dir/id.p12" -passout pass:vega \
  -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1
openssl x509 -in "$dir/cert.pem" -outform DER -out "$dir/cert.der"
echo "// expires: $(openssl x509 -in "$dir/cert.pem" -noout -enddate | cut -d= -f2)"
echo "identityP12:"
base64 < "$dir/id.p12" | tr -d '\n\r' | fold -w 76
echo
echo "certificateDER:"
base64 < "$dir/cert.der" | tr -d '\n\r' | fold -w 76
echo
