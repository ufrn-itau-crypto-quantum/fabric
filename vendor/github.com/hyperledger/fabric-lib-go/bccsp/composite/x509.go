/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"time"

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

// CheckCertificateSignature confere a assinatura composite de cert com a chave do emissor.
// Recusa o certificado quando o algoritmo externo e o algoritmo do TBS são diferentes.
func CheckCertificateSignature(cert *x509.Certificate, issuer *PublicKey) error {
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
	alg, err := algorithmFromIdentifier(ai)
	if err != nil {
		return err
	}
	if !alg.OID.Equal(issuer.Algorithm.OID) {
		return errors.Errorf("Certificate is signed with %s but the issuer key is %s", alg.Label, issuer.Algorithm.Label)
	}
	if outer.Signature.BitLength != len(outer.Signature.Bytes)*8 {
		return errors.New("Certificate signature is not a whole number of bytes")
	}
	// Certificados usam ctx vazio
	return Verify(issuer, outer.TBS.FullBytes, outer.Signature.Bytes, nil)
}

// IsCRLSignedWithComposite informa se o campo signatureAlgorithm da CRL é um OID composite.
func IsCRLSignedWithComposite(crl *pkix.CertificateList) bool {
	if crl == nil {
		return false
	}
	_, err := AlgorithmByOID(crl.SignatureAlgorithm.Algorithm)
	return err == nil
}

// CheckCRLSignature confere a assinatura composite de uma CRL com a chave do emissor. Recusa a CRL
// quando o algoritmo externo e o algoritmo do TBSCertList são diferentes ou têm o campo parameters.
func CheckCRLSignature(crl *pkix.CertificateList, issuer *PublicKey) error {
	if crl == nil || issuer == nil {
		return errors.New("CRL and issuer public key are required")
	}
	algID, err := AlgorithmIdentifier(issuer.Algorithm)
	if err != nil {
		return err
	}
	for _, ai := range []pkix.AlgorithmIdentifier{crl.SignatureAlgorithm, crl.TBSCertList.Signature} {
		der, err := asn1.Marshal(ai)
		if err != nil {
			return errors.WithMessage(err, "Failed to encode the CRL signature algorithm")
		}
		if !bytes.Equal(der, algID) {
			return errors.Errorf("CRL signature algorithm is not the one of the issuer key %s", issuer.Algorithm.Label)
		}
	}
	if crl.SignatureValue.BitLength != len(crl.SignatureValue.Bytes)*8 {
		return errors.New("CRL signature is not a whole number of bytes")
	}
	// CRLs usam ctx vazio.
	return Verify(issuer, crl.TBSCertList.Raw, crl.SignatureValue.Bytes, nil)
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

// VerifyOptions são as opções de VerifyChain. As raízes e as intermediárias vêm em listas.
type VerifyOptions struct {
	Roots         []*x509.Certificate
	Intermediates []*x509.Certificate
	CurrentTime   time.Time
	KeyUsages     []x509.ExtKeyUsage
}

// maxChainLength é o número máximo de certificados de uma cadeia.
const maxChainLength = 10

// VerifyChain verifica a cadeia de cert como x509.Certificate.Verify, com elos composite ou clássicos.
// Aplica as regras do crypto/x509: validade, BasicConstraints e KeyUsage do emissor, MaxPathLen,
// ExtKeyUsage e extensões críticas desconhecidas. Recusa cadeias com name constraints.
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
	// MaxPathLen conta as intermediárias abaixo do emissor e não vale para a raiz.
	if !isRoot && issuer.MaxPathLen >= 0 && len(chain)-1 > issuer.MaxPathLen {
		return errors.Errorf("Issuer '%s' allows at most %d intermediate certificates below it", issuer.Subject.CommonName, issuer.MaxPathLen)
	}
	if hasNameConstraints(issuer) {
		return errors.Errorf("Issuer '%s' has name constraints, which are not supported", issuer.Subject.CommonName)
	}

	if !IsSignedWithComposite(child) {
		return issuer.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
	}
	if !IsPKIXPublicKey(issuer.RawSubjectPublicKeyInfo) {
		return errors.Errorf("Certificate '%s' has a composite signature but the key of issuer '%s' is not composite", child.Subject.CommonName, issuer.Subject.CommonName)
	}
	issuerPub, err := ParsePKIXPublicKey(issuer.RawSubjectPublicKeyInfo)
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

// checkChainForKeyUsage reduz os usos pedidos a cada certificado com ExtKeyUsage e aceita a cadeia
// quando sobra algum uso. ExtKeyUsageAny permite todos.
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

// tbsSignatureAlgorithm devolve o DER do campo signature do tbsCertificate, depois de version e serialNumber.
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
