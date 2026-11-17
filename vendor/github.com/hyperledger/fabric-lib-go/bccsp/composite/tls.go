/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

// tlsSchemes maps the OID of each pair to its TLS 1.3 SignatureScheme, from the private-use range,
// and to the name the oqs-provider fork (D17) gives it. Peers that disagree on a codepoint fail to
// negotiate the pair without naming the cause.
var tlsSchemes = map[string]struct {
	name      string
	codepoint uint16
}{
	OIDMLDSA44ECDSAP256SHA256.String():        {"mldsa44_ecdsa_p256_sha256", 0xfe40},
	OIDMLDSA65ECDSAP384SHA512.String():        {"mldsa65_ecdsa_p384_sha512", 0xfe41},
	OIDMLDSA87ECDSAP384SHA512.String():        {"mldsa87_ecdsa_p384_sha512", 0xfe42},
	OIDSLHDSASHA2128sECDSAP256SHA256.String(): {"slhdsa_sha2_128s_ecdsa_p256_sha256", 0xfe43},
	OIDSLHDSASHA2128fECDSAP256SHA256.String(): {"slhdsa_sha2_128f_ecdsa_p256_sha256", 0xfe44},
	OIDSLHDSASHA2192sECDSAP384SHA512.String(): {"slhdsa_sha2_192s_ecdsa_p384_sha512", 0xfe45},
	OIDSLHDSASHA2192fECDSAP384SHA512.String(): {"slhdsa_sha2_192f_ecdsa_p384_sha512", 0xfe46},
	OIDSLHDSASHA2256sECDSAP384SHA512.String(): {"slhdsa_sha2_256s_ecdsa_p384_sha512", 0xfe47},
	OIDSLHDSASHA2256fECDSAP384SHA512.String(): {"slhdsa_sha2_256f_ecdsa_p384_sha512", 0xfe48},
}

// TLSCodepoint returns the TLS 1.3 SignatureScheme of alg, or 0 for a pair without one.
func TLSCodepoint(alg Algorithm) uint16 {
	return tlsSchemes[alg.OID.String()].codepoint
}

// TLSName returns the TLS signature algorithm name of alg in the oqs-provider fork, or "" for a
// pair without one.
func TLSName(alg Algorithm) string {
	return tlsSchemes[alg.OID.String()].name
}
