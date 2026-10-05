/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto/x509"
	"crypto/x509/pkix"

	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	"github.com/pkg/errors"
)

// setCompositeVerifyCerts guarda as raízes e as intermediárias de msp.opts em listas.
func (msp *bccspmsp) setCompositeVerifyCerts(roots, intermediates []*x509.Certificate) {
	msp.compositeRoots = roots
	msp.compositeIntermediates = intermediates
	msp.compositeChain = false
	for _, cert := range append(append([]*x509.Certificate{}, roots...), intermediates...) {
		if composite.IsPKIXPublicKey(cert.RawSubjectPublicKeyInfo) || composite.IsSignedWithComposite(cert) {
			msp.compositeChain = true
		}
	}
}

// isSupportedPublicKey aceita os algoritmos do mapa e, a partir do MSP v3, a chave composite pelo OID.
func (msp *bccspmsp) isSupportedPublicKey(cert *x509.Certificate) bool {
	if msp.supportedPublicKeyAlgorithms[cert.PublicKeyAlgorithm] {
		return true
	}
	return msp.compositeSupported && composite.IsPKIXPublicKey(cert.RawSubjectPublicKeyInfo)
}

// verifyChains usa composite.VerifyChain quando opts são os pools do MSP e a cadeia tem composite.
// Nos outros casos, como os pools de TLS, usa cert.Verify.
func (msp *bccspmsp) verifyChains(cert *x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	if !msp.compositeSupported || msp.opts == nil || opts.Roots != msp.opts.Roots || opts.Intermediates != msp.opts.Intermediates {
		return cert.Verify(opts)
	}
	if !msp.compositeChain && !composite.IsSignedWithComposite(cert) {
		return cert.Verify(opts)
	}
	return composite.VerifyChain(cert, composite.VerifyOptions{
		Roots:         msp.compositeRoots,
		Intermediates: msp.compositeIntermediates,
		CurrentTime:   opts.CurrentTime,
		KeyUsages:     opts.KeyUsages,
	})
}

// checkCRLSignature confere a assinatura da CRL com a chave do emissor.
func (msp *bccspmsp) checkCRLSignature(issuer *x509.Certificate, crl *pkix.CertificateList) error {
	if !composite.IsCRLSignedWithComposite(crl) {
		return issuer.CheckCRLSignature(crl)
	}
	pub, err := composite.ParsePKIXPublicKey(issuer.RawSubjectPublicKeyInfo)
	if err != nil {
		return errors.WithMessage(err, "the CRL has a composite signature but the issuer key is not composite")
	}
	return composite.CheckCRLSignature(crl, pub)
}
