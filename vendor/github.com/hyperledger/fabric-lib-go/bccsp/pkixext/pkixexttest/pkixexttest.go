/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package pkixexttest issues X.509 certificates whose keys or signatures belong to the schemes
// registered in pkixext, for tests in the modules that use them. crypto/x509 cannot create such
// certificates by itself.
package pkixexttest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/pkg/errors"
)

type certificate struct {
	TBS                asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Signature          asn1.BitString
}

// CreateCertificate issues tpl for pub, signed by priv on behalf of parent, like
// x509.CreateCertificate but also for keys of registered schemes. A nil parent self-signs.
//
// crypto/x509 builds the tbsCertificate with a throwaway ECDSA key; when pub or priv belongs to a
// registered scheme, the SubjectPublicKeyInfo, the signature algorithm and the signature are then
// replaced. An ECDSA signer signs the SHA-256 digest of the tbsCertificate.
func CreateCertificate(tpl, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) (*x509.Certificate, error) {
	if parent == nil {
		parent = tpl
	}
	spki, _ := pkixext.MarshalPKIXPublicKey(pub)
	sigAlg, _ := pkixext.AlgorithmIdentifier(priv.Public())
	throwaway, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	goPub, goPriv := pub, priv
	if spki != nil {
		goPub = throwaway.Public()
	}
	if sigAlg != nil {
		goPriv = throwaway
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, goPub, goPriv)
	if err != nil {
		return nil, err
	}
	if spki == nil && sigAlg == nil {
		return x509.ParseCertificate(der)
	}

	var outer certificate
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil, err
	}
	fields, err := splitSequence(outer.TBS.FullBytes)
	if err != nil {
		return nil, err
	}
	if len(fields) < 7 {
		return nil, errors.New("Unexpected tbsCertificate layout")
	}
	if sigAlg != nil {
		fields[2] = sigAlg
		outer.SignatureAlgorithm = asn1.RawValue{FullBytes: sigAlg}
	}
	if spki != nil {
		fields[6] = spki
	}
	tbs, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: concat(fields)})
	if err != nil {
		return nil, err
	}
	var signature []byte
	if sigAlg != nil {
		signature, err = priv.Sign(rand.Reader, tbs, crypto.Hash(0))
	} else {
		sum := sha256.Sum256(tbs)
		signature, err = priv.Sign(rand.Reader, sum[:], crypto.SHA256)
	}
	if err != nil {
		return nil, err
	}
	outer.TBS = asn1.RawValue{FullBytes: tbs}
	outer.Signature = asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}
	der, err = asn1.Marshal(outer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func splitSequence(der []byte) ([][]byte, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		return nil, err
	}
	var fields [][]byte
	for rest := seq.Bytes; len(rest) > 0; {
		var field asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			return nil, err
		}
		fields = append(fields, field.FullBytes)
	}
	return fields, nil
}

func concat(fields [][]byte) []byte {
	var out []byte
	for _, f := range fields {
		out = append(out, f...)
	}
	return out
}
