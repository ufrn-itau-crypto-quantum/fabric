/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package slhdsa

// TLSCodepoint returns the TLS 1.3 SignatureScheme of ps: 0x0911 to 0x091C in the order of the OID
// arcs .20 to .31, the assignment of OpenSSL 4.1 and oqs-provider. Peers that disagree on it fail
// to negotiate SLH-DSA without naming the cause.
func TLSCodepoint(ps ParameterSet) uint16 {
	return 0x0911 + uint16(ps.OID[len(ps.OID)-1]-20)
}
