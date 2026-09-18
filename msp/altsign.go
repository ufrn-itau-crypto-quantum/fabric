/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

// Verification of the ITU-T X.509 (2019) alternative signature, clause 9.8. It is the reading
// half of what fabric-ca issues in hybrid mode: the certificate carries the issuer's ML-DSA
// signature in the altSignatureValue extension, computed over a PreTBSCertificate.
//
// The PreTBSCertificate is the tbsCertificate without the signature field and without the
// altSignatureValue extension. Every other byte is kept exactly as the issuer encoded it, so the
// structure is rebuilt from the raw DER rather than re-encoded from a parsed certificate: a
// re-encoding that differs in one byte fails the signature with nothing pointing at the cause.

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/pkg/errors"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// The two extensions of the alternative signature. They must match
// util.OIDAltSignatureAlgorithm and util.OIDAltSignatureValue in fabric-ca.
var (
	oidAltSignatureAlgorithm = asn1.ObjectIdentifier{2, 5, 29, 73}
	oidAltSignatureValue     = asn1.ObjectIdentifier{2, 5, 29, 74}
)

// Context-specific tags of the optional tbsCertificate fields, per RFC 5280 §4.1.
var (
	tagVersion         = cbasn1.Tag(0).Constructed().ContextSpecific()
	tagIssuerUniqueID  = cbasn1.Tag(1).ContextSpecific()
	tagSubjectUniqueID = cbasn1.Tag(2).ContextSpecific()
	tagExtensions      = cbasn1.Tag(3).Constructed().ContextSpecific()
)

// hasAlternativeSignature reports whether a certificate carries an alternative signature.
func hasAlternativeSignature(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidAltSignatureValue) {
			return true
		}
	}
	return false
}

// verifyAlternativeSignature checks a certificate's alternative signature against the issuer's
// ML-DSA public key, the one the issuer's certificate carries in its altSubjectPublicKeyInfo
// extension.
func verifyAlternativeSignature(cert, issuer *x509.Certificate) error {
	issuerPub, found, err := altPublicKeyFromCert(issuer)
	if err != nil {
		return errors.WithMessage(err, "invalid alternative public key in the issuer certificate")
	}
	if !found {
		return errors.Errorf("issuer %s carries no alternative public key", issuer.Subject.CommonName)
	}

	level, found, err := altSignatureLevel(cert)
	if err != nil {
		return err
	}
	if !found {
		return errors.Errorf("certificate %s carries no alternative signature algorithm", cert.Subject.CommonName)
	}
	if level != issuerPub.Parameters().String() {
		return errors.Errorf("certificate %s announces %s but the issuer's alternative key is %s",
			cert.Subject.CommonName, level, issuerPub.Parameters())
	}

	signature, found, err := altSignatureValue(cert)
	if err != nil {
		return err
	}
	if !found {
		return errors.Errorf("certificate %s carries no alternative signature", cert.Subject.CommonName)
	}

	preTBS, err := preTBSCertificate(cert)
	if err != nil {
		return err
	}
	if err := mldsa.Verify(issuerPub, preTBS, signature, nil); err != nil {
		return errors.WithMessagef(err, "alternative signature of %s is invalid", cert.Subject.CommonName)
	}
	return nil
}

// validateAlternativeChain verifies the post-quantum chain running in parallel with the
// conventional one, from the identity up to the trust anchor.
//
// The requirement is decided by the trust anchor: when the root carries an alternative public
// key, every certificate below it must carry a valid alternative signature. Verifying only the
// certificates that happen to carry one would let an attacker strip the extensions and fall back
// to the conventional signature alone, which is exactly the protection being added here. A chain
// rooted at a conventional CA is left alone, which is what keeps existing MSPs working.
//
// The chain comes ordered from the identity to the root, as returned by x509.Certificate.Verify.
func validateAlternativeChain(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return errors.New("empty validation chain")
	}
	root := chain[len(chain)-1]
	_, rootIsHybrid, err := altPublicKeyFromCert(root)
	if err != nil {
		return errors.WithMessage(err, "invalid alternative public key in the root certificate")
	}
	if !rootIsHybrid {
		for _, cert := range chain {
			if hasAlternativeSignature(cert) {
				return errors.Errorf("certificate %s carries an alternative signature but the root %s has no alternative public key to verify it",
					cert.Subject.CommonName, root.Subject.CommonName)
			}
		}
		return nil
	}

	// A self-signed root anchors the chain with its own alternative key. A trust anchor that is
	// not self-signed was issued by a CA outside the chain, so its alternative signature cannot
	// be verified here: it is trusted by configuration, exactly as its conventional signature is.
	if bytes.Equal(root.RawIssuer, root.RawSubject) {
		if err := verifyAlternativeSignature(root, root); err != nil {
			return errors.WithMessage(err, "could not validate the root's alternative signature")
		}
	}
	for i := 0; i < len(chain)-1; i++ {
		if err := verifyAlternativeSignature(chain[i], chain[i+1]); err != nil {
			return errors.WithMessage(err, "could not validate the alternative certification chain")
		}
	}
	mspLogger.Debugf("Alternative certification chain of %s validated over %d certificates",
		chain[0].Subject.CommonName, len(chain))
	return nil
}

// altSignatureLevel returns the ML-DSA parameter set named by the altSignatureAlgorithm
// extension, as the string crypto/mldsa uses for its parameter sets.
func altSignatureLevel(cert *x509.Certificate) (level string, found bool, err error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidAltSignatureAlgorithm) {
			continue
		}
		var algorithm pkix.AlgorithmIdentifier
		rest, err := asn1.Unmarshal(ext.Value, &algorithm)
		if err != nil {
			return "", true, errors.WithMessage(err, "failed to decode the alternative signature algorithm")
		}
		if len(rest) != 0 {
			return "", true, errors.New("trailing data after the alternative signature algorithm")
		}
		name, err := mldsaParameterName(algorithm.Algorithm)
		if err != nil {
			return "", true, err
		}
		return name, true, nil
	}
	return "", false, nil
}

// altSignatureValue returns the signature carried by the altSignatureValue extension.
func altSignatureValue(cert *x509.Certificate) (signature []byte, found bool, err error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidAltSignatureValue) {
			continue
		}
		var bits asn1.BitString
		rest, err := asn1.Unmarshal(ext.Value, &bits)
		if err != nil {
			return nil, true, errors.WithMessage(err, "failed to decode the alternative signature")
		}
		if len(rest) != 0 {
			return nil, true, errors.New("trailing data after the alternative signature")
		}
		if bits.BitLength != len(bits.Bytes)*8 || len(bits.Bytes) == 0 {
			return nil, true, errors.New("alternative signature is not a whole number of bytes")
		}
		return bits.Bytes, true, nil
	}
	return nil, false, nil
}

// mldsaParameterName maps a FIPS 204 algorithm OID onto the crypto/mldsa parameter set name.
func mldsaParameterName(oid asn1.ObjectIdentifier) (string, error) {
	switch {
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}):
		return mldsa.MLDSA44().String(), nil
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}):
		return mldsa.MLDSA65().String(), nil
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}):
		return mldsa.MLDSA87().String(), nil
	default:
		return "", errors.Errorf("unrecognized ML-DSA algorithm OID %s", oid)
	}
}

// preTBSCertificate rebuilds the structure the alternative signature was computed over, by
// re-emitting the raw DER of the tbsCertificate without the signature field and without the
// altSignatureValue extension.
func preTBSCertificate(cert *x509.Certificate) ([]byte, error) {
	input := cryptobyte.String(cert.RawTBSCertificate)

	var tbs cryptobyte.String
	if !input.ReadASN1(&tbs, cbasn1.SEQUENCE) || !input.Empty() {
		return nil, errors.New("malformed tbsCertificate")
	}

	var version, serialNumber, issuer, validity, subject, spki []byte
	var issuerUniqueID, subjectUniqueID []byte

	if tbs.PeekASN1Tag(tagVersion) {
		if version = readDERElement(&tbs, tagVersion); version == nil {
			return nil, errors.New("malformed tbsCertificate: version")
		}
	}
	if serialNumber = readDERElement(&tbs, cbasn1.INTEGER); serialNumber == nil {
		return nil, errors.New("malformed tbsCertificate: serialNumber")
	}
	// The signature field is read only to be discarded: it is not part of the
	// PreTBSCertificate.
	if readDERElement(&tbs, cbasn1.SEQUENCE) == nil {
		return nil, errors.New("malformed tbsCertificate: signature")
	}
	for _, field := range []struct {
		name string
		dest *[]byte
	}{
		{"issuer", &issuer},
		{"validity", &validity},
		{"subject", &subject},
		{"subjectPublicKeyInfo", &spki},
	} {
		if *field.dest = readDERElement(&tbs, cbasn1.SEQUENCE); *field.dest == nil {
			return nil, errors.Errorf("malformed tbsCertificate: %s", field.name)
		}
	}
	if tbs.PeekASN1Tag(tagIssuerUniqueID) {
		issuerUniqueID = readDERElement(&tbs, tagIssuerUniqueID)
	}
	if tbs.PeekASN1Tag(tagSubjectUniqueID) {
		subjectUniqueID = readDERElement(&tbs, tagSubjectUniqueID)
	}

	var extensions [][]byte
	if tbs.PeekASN1Tag(tagExtensions) {
		var wrapper, list cryptobyte.String
		if !tbs.ReadASN1(&wrapper, tagExtensions) || !wrapper.ReadASN1(&list, cbasn1.SEQUENCE) {
			return nil, errors.New("malformed tbsCertificate: extensions")
		}
		for !list.Empty() {
			element := readDERElement(&list, cbasn1.SEQUENCE)
			if element == nil {
				return nil, errors.New("malformed tbsCertificate: extension element")
			}
			var ext pkix.Extension
			if _, err := asn1.Unmarshal(element, &ext); err != nil {
				return nil, errors.WithMessage(err, "failed to parse a certificate extension")
			}
			if ext.Id.Equal(oidAltSignatureValue) {
				continue
			}
			extensions = append(extensions, element)
		}
	}

	builder := cryptobyte.NewBuilder(nil)
	builder.AddASN1(cbasn1.SEQUENCE, func(pre *cryptobyte.Builder) {
		for _, field := range [][]byte{
			version, serialNumber, issuer, validity, subject, spki,
			issuerUniqueID, subjectUniqueID,
		} {
			pre.AddBytes(field)
		}
		if len(extensions) == 0 {
			return
		}
		pre.AddASN1(tagExtensions, func(wrapper *cryptobyte.Builder) {
			wrapper.AddASN1(cbasn1.SEQUENCE, func(list *cryptobyte.Builder) {
				for _, ext := range extensions {
					list.AddBytes(ext)
				}
			})
		})
	})
	return builder.Bytes()
}

func readDERElement(s *cryptobyte.String, tag cbasn1.Tag) []byte {
	var element cryptobyte.String
	if !s.ReadASN1Element(&element, tag) {
		return nil
	}
	return append([]byte(nil), element...)
}
