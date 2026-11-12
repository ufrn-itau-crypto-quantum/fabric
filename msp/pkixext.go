/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto/x509"
	"crypto/x509/pkix"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/pkg/errors"
)

// extVerifyCerts are the certificates behind a pair of verification pools, kept as lists because
// x509.CertPool cannot be enumerated. external tells whether any of them has a key or a signature
// of an algorithm outside crypto/x509.
type extVerifyCerts struct {
	roots, intermediates         *x509.CertPool
	rootCerts, intermediateCerts []*x509.Certificate
	external                     bool
}

func newExtVerifyCerts(opts *x509.VerifyOptions, roots, intermediates []*x509.Certificate) extVerifyCerts {
	all := append(append([]*x509.Certificate{}, roots...), intermediates...)
	return extVerifyCerts{
		roots:             opts.Roots,
		intermediates:     opts.Intermediates,
		rootCerts:         roots,
		intermediateCerts: intermediates,
		external:          pkixext.HasExternal(all),
	}
}

func (e extVerifyCerts) matches(opts x509.VerifyOptions) bool {
	return e.roots != nil && opts.Roots == e.roots && opts.Intermediates == e.intermediates
}

// isSupportedPublicKey accepts the algorithms of the map and, from MSP v3 on, a key of any scheme
// registered in pkixext, recognized by its OID.
func (msp *bccspmsp) isSupportedPublicKey(cert *x509.Certificate) bool {
	if msp.supportedPublicKeyAlgorithms[cert.PublicKeyAlgorithm] {
		return true
	}
	return msp.extSupported && pkixext.IsExternalPublicKey(cert.RawSubjectPublicKeyInfo)
}

// verifyChains uses pkixext.VerifyChain when opts are the identity pools or the TLS pools of the
// MSP, MSP v3 is on, and the pools or cert have an external algorithm. In every other case it uses
// cert.Verify.
func (msp *bccspmsp) verifyChains(cert *x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	if !msp.extSupported {
		return cert.Verify(opts)
	}
	var pools extVerifyCerts
	switch {
	case msp.extIdentity.matches(opts):
		pools = msp.extIdentity
	case msp.extTLS.matches(opts):
		pools = msp.extTLS
	default:
		return cert.Verify(opts)
	}
	if !pools.external && !pkixext.IsSignedWithExternal(cert) {
		return cert.Verify(opts)
	}
	return pkixext.VerifyChain(cert, pkixext.VerifyOptions{
		Roots:         pools.rootCerts,
		Intermediates: pools.intermediateCerts,
		CurrentTime:   opts.CurrentTime,
		KeyUsages:     opts.KeyUsages,
	})
}

func (msp *bccspmsp) checkCRLSignature(issuer *x509.Certificate, crl *pkix.CertificateList) error {
	if !pkixext.IsCRLSignedWithExternal(crl) {
		return issuer.CheckCRLSignature(crl)
	}
	pub, err := pkixext.ParsePKIXPublicKey(issuer.RawSubjectPublicKeyInfo)
	if err != nil {
		return errors.WithMessage(err, "the CRL has an external-algorithm signature but the issuer key is not of a registered external algorithm")
	}
	return pkixext.CheckCRLSignature(crl, pub)
}
