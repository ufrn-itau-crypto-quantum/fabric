/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pkixext

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"time"

	"github.com/pkg/errors"
)

type certificateOuter struct {
	TBS                asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Signature          asn1.BitString
}

// signatureScheme returns the scheme registered for the outer signatureAlgorithm of cert.
func signatureScheme(cert *x509.Certificate) (Scheme, bool) {
	if cert == nil {
		return nil, false
	}
	var outer certificateOuter
	if _, err := asn1.Unmarshal(cert.Raw, &outer); err != nil {
		return nil, false
	}
	var ai pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(outer.SignatureAlgorithm.FullBytes, &ai); err != nil {
		return nil, false
	}
	return SchemeByOID(ai.Algorithm)
}

// IsSignedWithExternal reports whether the signatureAlgorithm of cert belongs to a registered
// scheme.
func IsSignedWithExternal(cert *x509.Certificate) bool {
	_, ok := signatureScheme(cert)
	return ok
}

// IsCRLSignedWithExternal reports whether the signatureAlgorithm of the CRL belongs to a registered
// scheme.
func IsCRLSignedWithExternal(crl *pkix.CertificateList) bool {
	if crl == nil {
		return false
	}
	_, ok := SchemeByOID(crl.SignatureAlgorithm.Algorithm)
	return ok
}

// CheckCertificateSignature verifies the signature of cert with the issuer key, dispatching on the
// signature OID. The outer signatureAlgorithm must be byte-identical to the one in the
// tbsCertificate and to the AlgorithmIdentifier of the issuer key, which also rejects a parameters
// field that the key does not produce.
func CheckCertificateSignature(cert *x509.Certificate, issuer crypto.PublicKey) error {
	if cert == nil || issuer == nil {
		return errors.New("Certificate and issuer public key are required")
	}
	var outer certificateOuter
	rest, err := asn1.Unmarshal(cert.Raw, &outer)
	if err != nil {
		return errors.WithMessage(err, "Failed to decode the certificate")
	}
	if len(rest) != 0 {
		return errors.New("Trailing data after the certificate")
	}
	inner, err := tbsSignatureAlgorithm(outer.TBS.Bytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(inner, outer.SignatureAlgorithm.FullBytes) {
		return errors.New("Certificate signature algorithm differs from the one in the tbsCertificate")
	}

	var ai pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(outer.SignatureAlgorithm.FullBytes, &ai); err != nil {
		return errors.WithMessage(err, "Failed to decode the certificate signature algorithm")
	}
	s, ok := SchemeByOID(ai.Algorithm)
	if !ok {
		return errors.Errorf("Certificate signature algorithm %s belongs to no registered external algorithm", ai.Algorithm)
	}
	issuerAlgID, err := s.AlgorithmIdentifier(issuer)
	if err != nil {
		return errors.Errorf("Certificate is signed with %s %s but the issuer key is %T", s.Name(), ai.Algorithm, issuer)
	}
	if !bytes.Equal(issuerAlgID, outer.SignatureAlgorithm.FullBytes) {
		var issuerAI pkix.AlgorithmIdentifier
		_, _ = asn1.Unmarshal(issuerAlgID, &issuerAI)
		return errors.Errorf("Certificate is signed with %s but the issuer key is %s", ai.Algorithm, issuerAI.Algorithm)
	}
	if outer.Signature.BitLength != len(outer.Signature.Bytes)*8 {
		return errors.New("Certificate signature is not a whole number of bytes")
	}
	return s.Verify(issuer, outer.TBS.FullBytes, outer.Signature.Bytes)
}

// CheckCRLSignature verifies the signature of the CRL with the issuer key. Both the outer
// signatureAlgorithm and the one in the TBSCertList must equal the AlgorithmIdentifier of the
// issuer key.
func CheckCRLSignature(crl *pkix.CertificateList, issuer crypto.PublicKey) error {
	if crl == nil || issuer == nil {
		return errors.New("CRL and issuer public key are required")
	}
	s, ok := SchemeByOID(crl.SignatureAlgorithm.Algorithm)
	if !ok {
		return errors.Errorf("CRL signature algorithm %s belongs to no registered external algorithm", crl.SignatureAlgorithm.Algorithm)
	}
	algID, err := s.AlgorithmIdentifier(issuer)
	if err != nil {
		return errors.Errorf("CRL signature algorithm is not the one of the issuer key %T", issuer)
	}
	for _, ai := range []pkix.AlgorithmIdentifier{crl.SignatureAlgorithm, crl.TBSCertList.Signature} {
		der, err := asn1.Marshal(ai)
		if err != nil {
			return errors.WithMessage(err, "Failed to encode the CRL signature algorithm")
		}
		if !bytes.Equal(der, algID) {
			return errors.Errorf("CRL signature algorithm is not the one of the issuer key %s", s.Name())
		}
	}
	if crl.SignatureValue.BitLength != len(crl.SignatureValue.Bytes)*8 {
		return errors.New("CRL signature is not a whole number of bytes")
	}
	return s.Verify(issuer, crl.TBSCertList.Raw, crl.SignatureValue.Bytes)
}

// VerifyOptions are the options of VerifyChain. Roots and intermediates are plain lists.
type VerifyOptions struct {
	Roots         []*x509.Certificate
	Intermediates []*x509.Certificate
	CurrentTime   time.Time
	KeyUsages     []x509.ExtKeyUsage
}

const maxChainLength = 10

// VerifyChain verifies the chain of cert like x509.Certificate.Verify, with every link signed either
// by a crypto/x509 algorithm or by a registered scheme. The verifier of each link is chosen by the
// signature OID of that link, so chains mixing schemes are accepted.
//
// It applies the crypto/x509 rules: validity, issuer BasicConstraints and KeyUsage, MaxPathLen,
// ExtKeyUsage and unknown critical extensions. Chains with name constraints are rejected.
func VerifyChain(cert *x509.Certificate, opts VerifyOptions) ([][]*x509.Certificate, error) {
	if cert == nil {
		return nil, errors.New("Certificate is required")
	}
	if len(opts.Roots) == 0 {
		return nil, errors.New("No root certificates to verify the chain")
	}
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	keyUsages := opts.KeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	if err := checkCertificate(cert, now); err != nil {
		return nil, err
	}
	var chains [][]*x509.Certificate
	var lastErr error
	for _, root := range opts.Roots {
		if root.Equal(cert) {
			chains = append(chains, []*x509.Certificate{cert})
		}
	}
	if len(chains) == 0 {
		chains, lastErr = buildChains([]*x509.Certificate{cert}, opts, now)
	}

	var valid [][]*x509.Certificate
	for _, chain := range chains {
		if checkChainForKeyUsage(chain, keyUsages) {
			valid = append(valid, chain)
		}
	}
	if len(valid) > 0 {
		return valid, nil
	}
	if len(chains) > 0 {
		return nil, errors.New("Certificate specifies an incompatible key usage")
	}
	if lastErr != nil {
		return nil, errors.WithMessage(lastErr, "Certificate signed by unknown authority")
	}
	return nil, errors.New("Certificate signed by unknown authority")
}

func buildChains(chain []*x509.Certificate, opts VerifyOptions, now time.Time) ([][]*x509.Certificate, error) {
	child := chain[len(chain)-1]
	var chains [][]*x509.Certificate
	var lastErr error
	for _, root := range opts.Roots {
		if !bytes.Equal(root.RawSubject, child.RawIssuer) {
			continue
		}
		if err := checkIssuer(child, root, chain, now, true); err != nil {
			lastErr = err
			continue
		}
		chains = append(chains, append(slices.Clone(chain), root))
	}
	if len(chain)+1 >= maxChainLength {
		return chains, lastErr
	}
	for _, intermediate := range opts.Intermediates {
		if !bytes.Equal(intermediate.RawSubject, child.RawIssuer) || slices.ContainsFunc(chain, intermediate.Equal) {
			continue
		}
		if err := checkIssuer(child, intermediate, chain, now, false); err != nil {
			lastErr = err
			continue
		}
		longer, err := buildChains(append(slices.Clone(chain), intermediate), opts, now)
		if err != nil {
			lastErr = err
		}
		chains = append(chains, longer...)
	}
	return chains, lastErr
}

func checkCertificate(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.Errorf("Certificate '%s' has expired or is not yet valid", cert.Subject.CommonName)
	}
	if len(cert.UnhandledCriticalExtensions) > 0 {
		return errors.Errorf("Certificate '%s' has an unhandled critical extension", cert.Subject.CommonName)
	}
	return nil
}

// checkIssuer applies the CA rules to issuer and verifies the signature of child. MaxPathLen counts
// the intermediates below the issuer and does not apply to a root.
func checkIssuer(child, issuer *x509.Certificate, chain []*x509.Certificate, now time.Time, isRoot bool) error {
	if err := checkCertificate(issuer, now); err != nil {
		return err
	}
	if !issuer.BasicConstraintsValid || !issuer.IsCA {
		return errors.Errorf("Issuer '%s' is not a CA", issuer.Subject.CommonName)
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.Errorf("Issuer '%s' is not allowed to sign certificates", issuer.Subject.CommonName)
	}
	if !isRoot && issuer.MaxPathLen >= 0 && len(chain)-1 > issuer.MaxPathLen {
		return errors.Errorf("Issuer '%s' allows at most %d intermediate certificates below it", issuer.Subject.CommonName, issuer.MaxPathLen)
	}
	if hasNameConstraints(issuer) {
		return errors.Errorf("Issuer '%s' has name constraints, which are not supported", issuer.Subject.CommonName)
	}

	s, ok := signatureScheme(child)
	if !ok {
		return issuer.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
	}
	if keyScheme, ok := schemeOfSPKI(issuer.RawSubjectPublicKeyInfo); !ok || keyScheme != s {
		return errors.Errorf("Certificate '%s' has a %s signature but the key of issuer '%s' is not %s",
			child.Subject.CommonName, s.Name(), issuer.Subject.CommonName, s.Name())
	}
	issuerPub, err := s.ParsePKIXPublicKey(issuer.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}
	return CheckCertificateSignature(child, issuerPub)
}

func hasNameConstraints(cert *x509.Certificate) bool {
	return len(cert.PermittedDNSDomains) > 0 || len(cert.ExcludedDNSDomains) > 0 ||
		len(cert.PermittedIPRanges) > 0 || len(cert.ExcludedIPRanges) > 0 ||
		len(cert.PermittedEmailAddresses) > 0 || len(cert.ExcludedEmailAddresses) > 0 ||
		len(cert.PermittedURIDomains) > 0 || len(cert.ExcludedURIDomains) > 0
}

// checkChainForKeyUsage narrows the requested usages at every certificate with ExtKeyUsage and
// accepts the chain when some usage remains. ExtKeyUsageAny allows everything.
func checkChainForKeyUsage(chain []*x509.Certificate, keyUsages []x509.ExtKeyUsage) bool {
	if slices.Contains(keyUsages, x509.ExtKeyUsageAny) {
		return true
	}
	remaining := slices.Clone(keyUsages)
	for i := len(chain) - 1; i >= 0; i-- {
		cert := chain[i]
		if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
			continue
		}
		if slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageAny) {
			continue
		}
		remaining = slices.DeleteFunc(remaining, func(usage x509.ExtKeyUsage) bool {
			return !slices.Contains(cert.ExtKeyUsage, usage)
		})
		if len(remaining) == 0 {
			return false
		}
	}
	return true
}

// tbsSignatureAlgorithm returns the DER of the signature field of the tbsCertificate, which follows
// the optional version and the serialNumber.
func tbsSignatureAlgorithm(tbsContent []byte) ([]byte, error) {
	rest := tbsContent
	var element asn1.RawValue
	var err error
	if rest, err = asn1.Unmarshal(rest, &element); err != nil {
		return nil, errors.WithMessage(err, "Malformed tbsCertificate")
	}
	if element.Class == asn1.ClassContextSpecific && element.Tag == 0 {
		if rest, err = asn1.Unmarshal(rest, &element); err != nil {
			return nil, errors.WithMessage(err, "Malformed tbsCertificate: serialNumber")
		}
	}
	if _, err = asn1.Unmarshal(rest, &element); err != nil {
		return nil, errors.WithMessage(err, "Malformed tbsCertificate: signature")
	}
	return element.FullBytes, nil
}
