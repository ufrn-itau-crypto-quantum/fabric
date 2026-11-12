/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"

	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/pkg/errors"
)

// PQComponent is the post-quantum half of a composite pair. Keys are the crypto.PublicKey and
// crypto.Signer types of the component's own package, and the byte encodings are the raw ones that
// the draft concatenates with the ECDSA component.
type PQComponent interface {
	// Family names the algorithm in error messages, such as "ML-DSA".
	Family() string
	// Name names the parameter set, such as "ML-DSA-44".
	Name() string
	PublicKeySize() int
	PrivateKeySize() int
	SignatureSize() int
	GenerateKey() (crypto.Signer, error)
	ParsePublicKey(data []byte) (crypto.PublicKey, error)
	ParsePrivateKey(data []byte) (crypto.Signer, error)
	PublicKeyBytes(pub crypto.PublicKey) ([]byte, error)
	PrivateKeyBytes(priv crypto.Signer) ([]byte, error)
	// Sign and Verify take the composite Label as ctx, so the component signature is bound to the
	// pair.
	Sign(priv crypto.Signer, message, ctx []byte) ([]byte, error)
	Verify(pub crypto.PublicKey, message, signature, ctx []byte) error
}

// mldsaComponent is ML-DSA (FIPS 204). The private key is the 32-byte seed.
type mldsaComponent struct {
	level int
}

func (mldsaComponent) Family() string {
	return "ML-DSA"
}

func (c mldsaComponent) Name() string {
	return mustMLDSAParameters(c.level).String()
}

func (c mldsaComponent) PublicKeySize() int {
	size, _ := mldsaPublicKeySize(c.level)
	return size
}

func (mldsaComponent) PrivateKeySize() int {
	return mldsa.PrivateKeySize
}

func (c mldsaComponent) SignatureSize() int {
	size, _ := mldsaSignatureSize(c.level)
	return size
}

func (c mldsaComponent) GenerateKey() (crypto.Signer, error) {
	return mldsa.GenerateKey(mustMLDSAParameters(c.level))
}

func (c mldsaComponent) ParsePublicKey(data []byte) (crypto.PublicKey, error) {
	return mldsa.NewPublicKey(mustMLDSAParameters(c.level), data)
}

func (c mldsaComponent) ParsePrivateKey(data []byte) (crypto.Signer, error) {
	return mldsa.NewPrivateKey(mustMLDSAParameters(c.level), data)
}

func (mldsaComponent) PublicKeyBytes(pub crypto.PublicKey) ([]byte, error) {
	pk, ok := pub.(*mldsa.PublicKey)
	if !ok || pk == nil {
		return nil, errors.Errorf("%T is not an ML-DSA public key", pub)
	}
	return pk.Bytes(), nil
}

func (mldsaComponent) PrivateKeyBytes(priv crypto.Signer) ([]byte, error) {
	sk, ok := priv.(*mldsa.PrivateKey)
	if !ok || sk == nil {
		return nil, errors.Errorf("%T is not an ML-DSA private key", priv)
	}
	return sk.Bytes(), nil
}

func (mldsaComponent) Sign(priv crypto.Signer, message, ctx []byte) ([]byte, error) {
	sk, ok := priv.(*mldsa.PrivateKey)
	if !ok || sk == nil {
		return nil, errors.Errorf("%T is not an ML-DSA private key", priv)
	}
	return sk.Sign(nil, message, &mldsa.Options{Context: string(ctx)})
}

func (mldsaComponent) Verify(pub crypto.PublicKey, message, signature, ctx []byte) error {
	pk, ok := pub.(*mldsa.PublicKey)
	if !ok || pk == nil {
		return errors.Errorf("%T is not an ML-DSA public key", pub)
	}
	return mldsa.Verify(pk, message, signature, &mldsa.Options{Context: string(ctx)})
}

// mustMLDSAParameters panics on a level outside 44, 65 and 87; the table only holds valid levels.
func mustMLDSAParameters(level int) mldsa.Parameters {
	params, err := mldsaParametersForLevel(level)
	if err != nil {
		panic(err)
	}
	return params
}

// slhdsaComponent is pure SLH-DSA (FIPS 205) with randomized signing. The private key is
// SK.seed || SK.prf || PK.seed || PK.root.
type slhdsaComponent struct {
	params slhdsa.ParameterSet
}

func (slhdsaComponent) Family() string {
	return "SLH-DSA"
}

func (c slhdsaComponent) Name() string {
	return c.params.Name
}

func (c slhdsaComponent) PublicKeySize() int {
	return c.params.PublicKeySize()
}

func (c slhdsaComponent) PrivateKeySize() int {
	return c.params.PrivateKeySize()
}

func (c slhdsaComponent) SignatureSize() int {
	return c.params.SignatureSize()
}

func (c slhdsaComponent) GenerateKey() (crypto.Signer, error) {
	return slhdsa.GenerateKey(c.params)
}

func (c slhdsaComponent) ParsePublicKey(data []byte) (crypto.PublicKey, error) {
	return slhdsa.ParsePublicKey(c.params, data)
}

func (c slhdsaComponent) ParsePrivateKey(data []byte) (crypto.Signer, error) {
	return slhdsa.ParsePrivateKey(c.params, data)
}

func (c slhdsaComponent) PublicKeyBytes(pub crypto.PublicKey) ([]byte, error) {
	pk, err := c.publicKey(pub)
	if err != nil {
		return nil, err
	}
	return pk.Bytes()
}

func (c slhdsaComponent) PrivateKeyBytes(priv crypto.Signer) ([]byte, error) {
	sk, ok := priv.(*slhdsa.PrivateKey)
	if !ok || sk == nil || !sk.ParameterSet.OID.Equal(c.params.OID) {
		return nil, errors.Errorf("%T is not an %s private key", priv, c.params.Name)
	}
	return sk.Bytes()
}

func (c slhdsaComponent) Sign(priv crypto.Signer, message, ctx []byte) ([]byte, error) {
	sk, ok := priv.(*slhdsa.PrivateKey)
	if !ok || sk == nil || !sk.ParameterSet.OID.Equal(c.params.OID) {
		return nil, errors.Errorf("%T is not an %s private key", priv, c.params.Name)
	}
	return sk.Sign(rand.Reader, message, &slhdsa.SignerOpts{Context: ctx})
}

func (c slhdsaComponent) Verify(pub crypto.PublicKey, message, signature, ctx []byte) error {
	pk, err := c.publicKey(pub)
	if err != nil {
		return err
	}
	return slhdsa.Verify(pk, message, signature, ctx)
}

func (c slhdsaComponent) publicKey(pub crypto.PublicKey) (*slhdsa.PublicKey, error) {
	pk, ok := pub.(*slhdsa.PublicKey)
	if !ok || pk == nil || !pk.ParameterSet.OID.Equal(c.params.OID) {
		return nil, errors.Errorf("%T is not an %s public key", pub, c.params.Name)
	}
	return pk, nil
}
