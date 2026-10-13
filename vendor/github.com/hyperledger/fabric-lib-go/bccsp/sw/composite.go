/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
)

// compositeContext devolve o contexto das opções e recusa opções com hash.
func compositeContext(opts bccsp.SignerOpts) ([]byte, error) {
	if o, ok := opts.(*composite.SignerOpts); ok {
		if o == nil {
			return nil, nil
		}
		return o.Context, nil
	}
	if opts != nil && opts.HashFunc() != 0 {
		return nil, fmt.Errorf("Composite ML-DSA signs the whole message, not a %s digest", opts.HashFunc())
	}
	return nil, nil
}

func signComposite(k *composite.PrivateKey, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	ctx, err := compositeContext(opts)
	if err != nil {
		return nil, err
	}
	return k.Sign(rand.Reader, msg, &composite.SignerOpts{Context: ctx})
}

func verifyComposite(k *composite.PublicKey, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	ctx, err := compositeContext(opts)
	if err != nil {
		return false, err
	}
	if err := composite.Verify(k, msg, signature, ctx); err != nil {
		return false, nil
	}
	return true, nil
}

type compositeSigner struct{}

func (s *compositeSigner) Sign(k bccsp.Key, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return signComposite(k.(*compositePrivateKey).privKey, msg, opts)
}

type compositePrivateKeyVerifier struct{}

func (v *compositePrivateKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyComposite(k.(*compositePrivateKey).privKey.PublicKey(), signature, msg, opts)
}

type compositePublicKeyVerifier struct{}

func (v *compositePublicKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyComposite(k.(*compositePublicKey).pubKey, signature, msg, opts)
}

type compositeKeyGenerator struct{}

func (kg *compositeKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	o, ok := opts.(*bccsp.CompositeKeyGenOpts)
	if !ok || o == nil {
		return nil, errors.New("Invalid opts. Expected *bccsp.CompositeKeyGenOpts.")
	}
	alg, err := composite.AlgorithmByOID(o.OID)
	if err != nil {
		return nil, err
	}
	privKey, err := composite.GenerateKey(alg)
	if err != nil {
		return nil, fmt.Errorf("Failed generating %s key: [%s]", alg.Label, err)
	}
	return &compositePrivateKey{privKey}, nil
}

type compositePrivateKeyImportOptsKeyImporter struct{}

func (*compositePrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[CompositePrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}
	if len(der) == 0 {
		return nil, errors.New("[CompositePrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}
	privKey, err := composite.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKCS#8 to Composite ML-DSA private key [%s]", err)
	}
	return &compositePrivateKey{privKey}, nil
}

type compositePKIXPublicKeyImportOptsKeyImporter struct{}

func (*compositePKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[CompositePKIXPublicKeyImportOpts] Invalid raw material. Expected byte array.")
	}
	if len(der) == 0 {
		return nil, errors.New("[CompositePKIXPublicKeyImportOpts] Invalid raw. It must not be nil.")
	}
	pubKey, err := composite.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to Composite ML-DSA public key [%s]", err)
	}
	return &compositePublicKey{pubKey}, nil
}

type compositeGoPublicKeyImportOptsKeyImporter struct{}

func (*compositeGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	pubKey, ok := raw.(*composite.PublicKey)
	if !ok || pubKey == nil {
		return nil, errors.New("Invalid raw material. Expected *composite.PublicKey.")
	}
	return &compositePublicKey{pubKey}, nil
}
