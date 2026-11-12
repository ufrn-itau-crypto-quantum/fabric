/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package slhdsa implements pure SLH-DSA (FIPS 205) keys and signatures, with the X.509
// encodings of RFC 9909, on top of github.com/cloudflare/circl/sign/slhdsa.
//
// The package does not depend on the BCCSP. The rest of Fabric handles only the types defined
// here, so the underlying library can be swapped without touching the callers.
package slhdsa

import (
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"io"

	circl "github.com/cloudflare/circl/sign/slhdsa"
	"github.com/pkg/errors"
)

// ParameterSet is one of the twelve SLH-DSA parameter sets of FIPS 205, identified by its pure
// SLH-DSA OID from RFC 9909.
type ParameterSet struct {
	Name string
	OID  asn1.ObjectIdentifier
	id   circl.ID
}

var (
	SHA2_128s  = ParameterSet{"SLH-DSA-SHA2-128s", oidSLHDSA(20), circl.SHA2_128s}
	SHA2_128f  = ParameterSet{"SLH-DSA-SHA2-128f", oidSLHDSA(21), circl.SHA2_128f}
	SHA2_192s  = ParameterSet{"SLH-DSA-SHA2-192s", oidSLHDSA(22), circl.SHA2_192s}
	SHA2_192f  = ParameterSet{"SLH-DSA-SHA2-192f", oidSLHDSA(23), circl.SHA2_192f}
	SHA2_256s  = ParameterSet{"SLH-DSA-SHA2-256s", oidSLHDSA(24), circl.SHA2_256s}
	SHA2_256f  = ParameterSet{"SLH-DSA-SHA2-256f", oidSLHDSA(25), circl.SHA2_256f}
	SHAKE_128s = ParameterSet{"SLH-DSA-SHAKE-128s", oidSLHDSA(26), circl.SHAKE_128s}
	SHAKE_128f = ParameterSet{"SLH-DSA-SHAKE-128f", oidSLHDSA(27), circl.SHAKE_128f}
	SHAKE_192s = ParameterSet{"SLH-DSA-SHAKE-192s", oidSLHDSA(28), circl.SHAKE_192s}
	SHAKE_192f = ParameterSet{"SLH-DSA-SHAKE-192f", oidSLHDSA(29), circl.SHAKE_192f}
	SHAKE_256s = ParameterSet{"SLH-DSA-SHAKE-256s", oidSLHDSA(30), circl.SHAKE_256s}
	SHAKE_256f = ParameterSet{"SLH-DSA-SHAKE-256f", oidSLHDSA(31), circl.SHAKE_256f}
)

var parameterSets = []ParameterSet{
	SHA2_128s, SHA2_128f, SHA2_192s, SHA2_192f, SHA2_256s, SHA2_256f,
	SHAKE_128s, SHAKE_128f, SHAKE_192s, SHAKE_192f, SHAKE_256s, SHAKE_256f,
}

// oidSLHDSA returns 2.16.840.1.101.3.4.3.<arc>, the NIST sigAlgs arc used by RFC 9909.
func oidSLHDSA(arc int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, arc}
}

func ParameterSets() []ParameterSet {
	return append([]ParameterSet(nil), parameterSets...)
}

// ParameterSetByOID accepts only the pure SLH-DSA OIDs. A HashSLH-DSA OID is reported as
// unsupported, because RFC 9909 binds the key to one signing mode.
func ParameterSetByOID(oid asn1.ObjectIdentifier) (ParameterSet, error) {
	for _, ps := range parameterSets {
		if ps.OID.Equal(oid) {
			return ps, nil
		}
	}
	return ParameterSet{}, errors.Errorf("Unsupported SLH-DSA OID: %s", oid)
}

func (ps ParameterSet) PublicKeySize() int {
	return ps.id.Scheme().PublicKeySize()
}

func (ps ParameterSet) PrivateKeySize() int {
	return ps.id.Scheme().PrivateKeySize()
}

func (ps ParameterSet) SignatureSize() int {
	return ps.id.Scheme().SignatureSize()
}

func (ps ParameterSet) String() string {
	return ps.Name
}

type PublicKey struct {
	ParameterSet ParameterSet
	key          circl.PublicKey
}

type PrivateKey struct {
	ParameterSet ParameterSet
	key          circl.PrivateKey
}

var _ crypto.Signer = (*PrivateKey)(nil)

// SignerOpts passes a FIPS 205 context string to Sign. With nil opts the context is empty, which
// is what RFC 9909 requires for certificates and CRLs.
type SignerOpts struct {
	Context []byte
}

func (*SignerOpts) HashFunc() crypto.Hash {
	return 0
}

func GenerateKey(ps ParameterSet) (*PrivateKey, error) {
	_, sk, err := circl.GenerateKey(rand.Reader, ps.id)
	if err != nil {
		return nil, errors.WithMessagef(err, "Failed to generate the %s key", ps.Name)
	}
	return &PrivateKey{ParameterSet: ps, key: sk}, nil
}

// ParsePublicKey decodes PK.seed || PK.root, which must be exactly 2n bytes for the set.
func ParsePublicKey(ps ParameterSet, data []byte) (*PublicKey, error) {
	if len(data) != ps.PublicKeySize() {
		return nil, errors.Errorf("%s public key must be %d bytes, got %d", ps.Name, ps.PublicKeySize(), len(data))
	}
	key := circl.PublicKey{ID: ps.id}
	if err := key.UnmarshalBinary(data); err != nil {
		return nil, errors.WithMessagef(err, "Invalid %s public key", ps.Name)
	}
	return &PublicKey{ParameterSet: ps, key: key}, nil
}

func (pk *PublicKey) Bytes() ([]byte, error) {
	return pk.key.MarshalBinary()
}

func (pk *PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*PublicKey)
	return ok && pk.ParameterSet.OID.Equal(other.ParameterSet.OID) && pk.key.Equal(other.key)
}

// ParsePrivateKey decodes SK.seed || SK.prf || PK.seed || PK.root, which must be exactly 4n bytes
// for the set. PK.root is taken as given and not recomputed from the seeds.
func ParsePrivateKey(ps ParameterSet, data []byte) (*PrivateKey, error) {
	if len(data) != ps.PrivateKeySize() {
		return nil, errors.Errorf("%s private key must be %d bytes, got %d", ps.Name, ps.PrivateKeySize(), len(data))
	}
	key := circl.PrivateKey{ID: ps.id}
	if err := key.UnmarshalBinary(data); err != nil {
		return nil, errors.WithMessagef(err, "Invalid %s private key", ps.Name)
	}
	return &PrivateKey{ParameterSet: ps, key: key}, nil
}

func (sk *PrivateKey) Bytes() ([]byte, error) {
	return sk.key.MarshalBinary()
}

func (sk *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{ParameterSet: sk.ParameterSet, key: sk.key.PublicKey()}
}

func (sk *PrivateKey) Public() crypto.PublicKey {
	return sk.PublicKey()
}

func (sk *PrivateKey) Equal(x crypto.PrivateKey) bool {
	other, ok := x.(*PrivateKey)
	return ok && sk.ParameterSet.OID.Equal(other.ParameterSet.OID) && sk.key.Equal(other.key)
}

// Sign produces a randomized pure SLH-DSA signature over the whole message. The context comes from
// a *SignerOpts; any other opts with a non-zero HashFunc is rejected, since a digest passed as
// the message would be signed as if it were the message. A nil random uses crypto/rand.
func (sk *PrivateKey) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	var ctx []byte
	if o, ok := opts.(*SignerOpts); ok && o != nil {
		ctx = o.Context
	} else if opts != nil && opts.HashFunc() != 0 {
		return nil, errors.Errorf("SLH-DSA signs the whole message, not a %s digest", opts.HashFunc())
	}
	if random == nil {
		random = rand.Reader
	}
	sig, err := circl.SignRandomized(&sk.key, random, circl.NewMessage(message), ctx)
	if err != nil {
		return nil, errors.WithMessagef(err, "Failed to compute the %s signature", sk.ParameterSet.Name)
	}
	return sig, nil
}

func Verify(pk *PublicKey, message, signature, ctx []byte) error {
	if len(signature) != pk.ParameterSet.SignatureSize() {
		return errors.Errorf("%s signature must be %d bytes, got %d",
			pk.ParameterSet.Name, pk.ParameterSet.SignatureSize(), len(signature))
	}
	if !circl.Verify(&pk.key, circl.NewMessage(message), signature, ctx) {
		return errors.Errorf("Invalid %s signature", pk.ParameterSet.Name)
	}
	return nil
}
