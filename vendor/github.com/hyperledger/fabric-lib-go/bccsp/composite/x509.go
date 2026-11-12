/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/pkg/errors"
)

// AlgorithmIdentifier devolve o AlgorithmIdentifier DER do par, sem o campo parameters.
func AlgorithmIdentifier(alg Algorithm) ([]byte, error) {
	return asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: alg.OID})
}

// SubjectKeyID calcula o SHA-1 da chave pública composta bruta, pelo método 1 da RFC 5280 §4.2.1.2.
func SubjectKeyID(pub *PublicKey) ([]byte, error) {
	raw, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(raw)
	return sum[:], nil
}

type certificateOuter struct {
	TBS                asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Signature          asn1.BitString
}

// CheckCertificateSignature verifies the composite signature of cert with the issuer key. See
// pkixext.CheckCertificateSignature.
func CheckCertificateSignature(cert *x509.Certificate, issuer *PublicKey) error {
	if cert == nil || issuer == nil {
		return errors.New("Certificate and issuer public key are required")
	}
	return pkixext.CheckCertificateSignature(cert, issuer)
}

// IsCRLSignedWithComposite informa se o campo signatureAlgorithm da CRL é um OID composite.
func IsCRLSignedWithComposite(crl *pkix.CertificateList) bool {
	if crl == nil {
		return false
	}
	_, err := AlgorithmByOID(crl.SignatureAlgorithm.Algorithm)
	return err == nil
}

// CheckCRLSignature verifies the composite signature of a CRL with the issuer key. See
// pkixext.CheckCRLSignature.
func CheckCRLSignature(crl *pkix.CertificateList, issuer *PublicKey) error {
	if crl == nil || issuer == nil {
		return errors.New("CRL and issuer public key are required")
	}
	return pkixext.CheckCRLSignature(crl, issuer)
}

// IsSignedWithComposite informa se o campo signatureAlgorithm de cert é um OID composite.
func IsSignedWithComposite(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	var outer certificateOuter
	if _, err := asn1.Unmarshal(cert.Raw, &outer); err != nil {
		return false
	}
	var ai pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(outer.SignatureAlgorithm.FullBytes, &ai); err != nil {
		return false
	}
	_, err := AlgorithmByOID(ai.Algorithm)
	return err == nil
}

type VerifyOptions = pkixext.VerifyOptions

// VerifyChain verifies the chain of cert with links of any registered scheme or classical. See
// pkixext.VerifyChain.
func VerifyChain(cert *x509.Certificate, opts VerifyOptions) ([][]*x509.Certificate, error) {
	return pkixext.VerifyChain(cert, opts)
}
