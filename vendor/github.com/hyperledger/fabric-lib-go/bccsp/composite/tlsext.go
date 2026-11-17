//go:build tlsext

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
)

// init registers every pair with a codepoint in crypto/tls for the TLS 1.3 CertificateVerify, which
// is verified with the empty context. It needs the toolchain of blockchain/src/go-tlsext: with the
// official Go, tls.RegisterSignatureScheme does not exist and a build with the tlsext tag fails.
func init() {
	for _, alg := range algorithms {
		codepoint := TLSCodepoint(alg)
		if codepoint == 0 {
			continue
		}
		owns := func(pub crypto.PublicKey) bool {
			k, ok := pub.(*PublicKey)
			return ok && k != nil && k.Algorithm.OID.Equal(alg.OID)
		}
		tls.RegisterSignatureScheme(tls.SignatureSchemeExtension{
			Scheme: tls.SignatureScheme(codepoint),
			Owns:   owns,
			ParsePublicKey: func(cert *x509.Certificate) (crypto.PublicKey, bool) {
				pub, err := ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
				if err != nil || !owns(pub) {
					return nil, false
				}
				return pub, true
			},
			Verify: func(pub crypto.PublicKey, signed, sig []byte) error {
				return Verify(pub.(*PublicKey), signed, sig, nil)
			},
		})
		pkixext.RecordTLSScheme(pkixext.TLSScheme{Name: TLSName(alg), Codepoint: codepoint})
	}
}
