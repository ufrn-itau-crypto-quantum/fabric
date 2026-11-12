/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package pkixext handles X.509 keys and signatures whose algorithms crypto/x509 does not know,
// such as Composite ML-DSA and SLH-DSA, through a registry keyed by algorithm OID.
//
// Each algorithm package registers its Scheme from its own init function, so this package does not
// import any of them. A scheme whose package is not linked into the binary is simply unknown: its
// keys are not recognized as external and its signatures fail to verify.
package pkixext

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"sync"

	"github.com/pkg/errors"
)

// Scheme is one family of algorithms outside crypto/x509. Every OID returned by OIDs is used both
// as the SubjectPublicKeyInfo algorithm of the key and as the signature algorithm it produces.
//
// Certificates and CRLs are signed with an empty context, so Verify takes none.
type Scheme interface {
	// Name is used in error messages.
	Name() string
	OIDs() []asn1.ObjectIdentifier
	ParsePKIXPublicKey(spki []byte) (crypto.PublicKey, error)
	// MarshalPKIXPublicKey returns an error when the key does not belong to this scheme.
	MarshalPKIXPublicKey(pub crypto.PublicKey) ([]byte, error)
	ParsePKCS8PrivateKey(der []byte) (crypto.Signer, error)
	Verify(pub crypto.PublicKey, message, signature []byte) error
	// AlgorithmIdentifier returns the DER AlgorithmIdentifier of the key, or an error when the key
	// does not belong to this scheme.
	AlgorithmIdentifier(pub crypto.PublicKey) ([]byte, error)
	SubjectKeyID(pub crypto.PublicKey) ([]byte, error)
}

// ErrNotExternal reports an SPKI whose OID belongs to no registered scheme.
var ErrNotExternal = errors.New("not a key of a registered external algorithm")

var (
	registryMu sync.RWMutex
	schemes    []Scheme
	byOID      = map[string]Scheme{}
)

// Register adds s to the registry. It panics when one of the OIDs is already registered, since two
// schemes answering for the same OID would make the dispatch depend on registration order.
func Register(s Scheme) {
	registryMu.Lock()
	defer registryMu.Unlock()
	for _, oid := range s.OIDs() {
		if prev, ok := byOID[oid.String()]; ok {
			panic(fmt.Sprintf("pkixext: OID %s registered by both %s and %s", oid, prev.Name(), s.Name()))
		}
	}
	for _, oid := range s.OIDs() {
		byOID[oid.String()] = s
	}
	schemes = append(schemes, s)
}

func SchemeByOID(oid asn1.ObjectIdentifier) (Scheme, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	s, ok := byOID[oid.String()]
	return s, ok
}

// SchemeForKey returns the scheme whose AlgorithmIdentifier accepts pub.
func SchemeForKey(pub crypto.PublicKey) (Scheme, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	for _, s := range schemes {
		if _, err := s.AlgorithmIdentifier(pub); err == nil {
			return s, true
		}
	}
	return nil, false
}

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func schemeOfSPKI(spki []byte) (Scheme, bool) {
	var info subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		return nil, false
	}
	return SchemeByOID(info.Algorithm.Algorithm)
}

// IsExternalPublicKey reports whether the SPKI carries the OID of a registered scheme, without
// validating the key.
func IsExternalPublicKey(spki []byte) bool {
	_, ok := schemeOfSPKI(spki)
	return ok
}

// ParsePKIXPublicKey returns ErrNotExternal when the OID belongs to no registered scheme.
func ParsePKIXPublicKey(spki []byte) (crypto.PublicKey, error) {
	s, ok := schemeOfSPKI(spki)
	if !ok {
		return nil, ErrNotExternal
	}
	return s.ParsePKIXPublicKey(spki)
}

// ParsePKCS8PrivateKey returns ErrNotExternal when the OID belongs to no registered scheme.
func ParsePKCS8PrivateKey(der []byte) (crypto.Signer, error) {
	var info struct {
		Version   int
		Algorithm pkix.AlgorithmIdentifier
		Rest      asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, ErrNotExternal
	}
	s, ok := SchemeByOID(info.Algorithm.Algorithm)
	if !ok {
		return nil, ErrNotExternal
	}
	return s.ParsePKCS8PrivateKey(der)
}

func MarshalPKIXPublicKey(pub crypto.PublicKey) ([]byte, error) {
	s, ok := SchemeForKey(pub)
	if !ok {
		return nil, errors.Errorf("%T is not a key of a registered external algorithm", pub)
	}
	return s.MarshalPKIXPublicKey(pub)
}

func AlgorithmIdentifier(pub crypto.PublicKey) ([]byte, error) {
	s, ok := SchemeForKey(pub)
	if !ok {
		return nil, errors.Errorf("%T is not a key of a registered external algorithm", pub)
	}
	return s.AlgorithmIdentifier(pub)
}

func SubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	s, ok := SchemeForKey(pub)
	if !ok {
		return nil, errors.Errorf("%T is not a key of a registered external algorithm", pub)
	}
	return s.SubjectKeyID(pub)
}
