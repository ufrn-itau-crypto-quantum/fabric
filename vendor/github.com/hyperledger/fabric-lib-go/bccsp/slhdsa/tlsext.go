//go:build tlsext

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package slhdsa

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
)

// init registers every parameter set in crypto/tls for the TLS 1.3 CertificateVerify. It needs the
// toolchain of blockchain/src/go-tlsext: with the official Go, tls.RegisterSignatureScheme does not
// exist and a build with the tlsext tag fails.
func init() {
	for _, ps := range parameterSets {
		owns := func(pub crypto.PublicKey) bool {
			k, ok := pub.(*PublicKey)
			return ok && k.ParameterSet.OID.Equal(ps.OID)
		}
		tls.RegisterSignatureScheme(tls.SignatureSchemeExtension{
			Scheme: tls.SignatureScheme(TLSCodepoint(ps)),
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
		pkixext.RecordTLSScheme(pkixext.TLSScheme{Name: ps.Name, Codepoint: TLSCodepoint(ps)})
	}
}
