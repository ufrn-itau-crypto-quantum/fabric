/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto/mldsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/pkg/errors"
)

// Support for hybrid certificates issued by fabric-ca with csr.keyrequest.algo =
// mldsa-hybrid: the SubjectPublicKeyInfo stays classical and the ML-DSA public key travels in
// the non-critical altSubjectPublicKeyInfo extension.
//
// The MSP still anchors the identity on the classical key; what it does here is refuse a
// certificate whose alternative key is malformed. Making ML-DSA the authenticating factor
// would additionally require the signing side to use the key in the extension.

// oidAltSubjectPublicKeyInfo is the X.509v3 extension carrying an alternative public key.
// ITU-T X.509 (2019), clause 9.8. It must match util.OIDAltSubjectPublicKeyInfo in fabric-ca.
var oidAltSubjectPublicKeyInfo = asn1.ObjectIdentifier{2, 5, 29, 72}

// altPublicKeyFromCert returns the ML-DSA public key carried by a certificate.
// found is false, with no error, when the extension is absent.
func altPublicKeyFromCert(cert *x509.Certificate) (pub *mldsa.PublicKey, found bool, err error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidAltSubjectPublicKeyInfo) {
			continue
		}
		pub, err := parseAltPublicKey(ext)
		if err != nil {
			return nil, true, err
		}
		return pub, true, nil
	}
	return nil, false, nil
}

// parseAltPublicKey decodes the extension value, which is a SubjectPublicKeyInfo in DER.
func parseAltPublicKey(ext pkix.Extension) (*mldsa.PublicKey, error) {
	if len(ext.Value) == 0 {
		return nil, errors.New("alternative public key info is empty")
	}
	key, err := x509.ParsePKIXPublicKey(ext.Value)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to decode alternative public key info")
	}
	pub, ok := key.(*mldsa.PublicKey)
	if !ok {
		return nil, errors.Errorf("alternative public key is not an ML-DSA key, got %T", key)
	}
	return pub, nil
}

// validateAltPublicKey rejects a certificate whose alternative public key extension is
// present but unusable. A certificate without the extension is valid, since the hybrid mode
// is optional.
func validateAltPublicKey(cert *x509.Certificate) error {
	pub, found, err := altPublicKeyFromCert(cert)
	if err != nil {
		return errors.WithMessage(err, "invalid alternative public key extension")
	}
	if !found {
		return nil
	}
	mspIdentityLogger.Debugf("Identity carries an %s alternative public key", pub.Parameters())
	return nil
}
