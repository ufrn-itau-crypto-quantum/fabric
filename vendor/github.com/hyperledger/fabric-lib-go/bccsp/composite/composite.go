/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"io"

	"github.com/pkg/errors"
)

// Algorithm descreve um par composite ML-DSA do draft-ietf-lamps-pq-composite-sigs-19.
type Algorithm struct {
	OID        asn1.ObjectIdentifier
	Label      string
	MLDSALevel int
	// Hash é o PH que resume a mensagem dentro do M'.
	Hash     crypto.Hash
	Curve    elliptic.Curve
	CurveOID asn1.ObjectIdentifier
	// TraditionalHash é o hash que o ECDSA aplica ao M'. Nos pares P-384, ele é diferente de Hash.
	TraditionalHash crypto.Hash
}

var (
	OIDMLDSA44ECDSAP256SHA256 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 40}
	OIDMLDSA65ECDSAP384SHA512 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 46}
	OIDMLDSA87ECDSAP384SHA512 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 49}

	oidCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
)

var algorithms = []Algorithm{
	{
		OID:             OIDMLDSA44ECDSAP256SHA256,
		Label:           "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
		MLDSALevel:      44,
		Hash:            crypto.SHA256,
		Curve:           elliptic.P256(),
		CurveOID:        oidCurveP256,
		TraditionalHash: crypto.SHA256,
	},
	{
		OID:             OIDMLDSA65ECDSAP384SHA512,
		Label:           "COMPSIG-MLDSA65-ECDSA-P384-SHA512",
		MLDSALevel:      65,
		Hash:            crypto.SHA512,
		Curve:           elliptic.P384(),
		CurveOID:        oidCurveP384,
		TraditionalHash: crypto.SHA384,
	},
	{
		OID:             OIDMLDSA87ECDSAP384SHA512,
		Label:           "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
		MLDSALevel:      87,
		Hash:            crypto.SHA512,
		Curve:           elliptic.P384(),
		CurveOID:        oidCurveP384,
		TraditionalHash: crypto.SHA384,
	},
}

func AlgorithmByOID(oid asn1.ObjectIdentifier) (Algorithm, error) {
	for _, alg := range algorithms {
		if alg.OID.Equal(oid) {
			return alg, nil
		}
	}
	return Algorithm{}, errors.Errorf("Unsupported Composite ML-DSA OID: %s", oid)
}

func AlgorithmForLevel(level int) (Algorithm, error) {
	for _, alg := range algorithms {
		if alg.MLDSALevel == level {
			return alg, nil
		}
	}
	return Algorithm{}, errors.Errorf("Invalid MLDSA key size for Composite ML-DSA: %d (expecting 44, 65 or 87)", level)
}

func mldsaParametersForLevel(level int) (mldsa.Parameters, error) {
	switch level {
	case 44:
		return mldsa.MLDSA44(), nil
	case 65:
		return mldsa.MLDSA65(), nil
	case 87:
		return mldsa.MLDSA87(), nil
	default:
		return mldsa.Parameters{}, errors.Errorf("Invalid MLDSA key size: %d (expecting 44, 65 or 87)", level)
	}
}

func mldsaPublicKeySize(level int) (int, error) {
	switch level {
	case 44:
		return mldsa.MLDSA44PublicKeySize, nil
	case 65:
		return mldsa.MLDSA65PublicKeySize, nil
	case 87:
		return mldsa.MLDSA87PublicKeySize, nil
	default:
		return 0, errors.Errorf("Invalid MLDSA key size: %d (expecting 44, 65 or 87)", level)
	}
}

func mldsaSignatureSize(level int) (int, error) {
	switch level {
	case 44:
		return mldsa.MLDSA44SignatureSize, nil
	case 65:
		return mldsa.MLDSA65SignatureSize, nil
	case 87:
		return mldsa.MLDSA87SignatureSize, nil
	default:
		return 0, errors.Errorf("Invalid MLDSA key size: %d (expecting 44, 65 or 87)", level)
	}
}

func SerializePublicKey(mldsaPK, tradPK []byte) []byte {
	return concat(mldsaPK, tradPK)
}

// DeserializePublicKey separa a chave pública nas partes ML-DSA e clássica. O tamanho da parte clássica não é verificado.
func DeserializePublicKey(alg Algorithm, data []byte) (mldsaPK, tradPK []byte, err error) {
	size, err := mldsaPublicKeySize(alg.MLDSALevel)
	if err != nil {
		return nil, nil, err
	}
	if len(data) <= size {
		return nil, nil, errors.Errorf("Composite public key too short for ML-DSA-%d: got %d bytes, need more than %d",
			alg.MLDSALevel, len(data), size)
	}
	return data[:size], data[size:], nil
}

// SerializePrivateKey concatena a seed ML-DSA de 32 bytes e a chave privada clássica.
func SerializePrivateKey(mldsaSeed, tradSK []byte) []byte {
	return concat(mldsaSeed, tradSK)
}

func DeserializePrivateKey(data []byte) (mldsaSeed, tradSK []byte, err error) {
	if len(data) <= mldsa.PrivateKeySize {
		return nil, nil, errors.Errorf("Composite private key too short: got %d bytes, need more than %d",
			len(data), mldsa.PrivateKeySize)
	}
	return data[:mldsa.PrivateKeySize], data[mldsa.PrivateKeySize:], nil
}

func SerializeSignatureValue(mldsaSig, tradSig []byte) []byte {
	return concat(mldsaSig, tradSig)
}

// DeserializeSignatureValue separa a assinatura no tamanho fixo da assinatura ML-DSA. O resto é a assinatura ECDSA em DER.
func DeserializeSignatureValue(alg Algorithm, data []byte) (mldsaSig, tradSig []byte, err error) {
	size, err := mldsaSignatureSize(alg.MLDSALevel)
	if err != nil {
		return nil, nil, err
	}
	if len(data) <= size {
		return nil, nil, errors.Errorf("Composite signature too short for ML-DSA-%d: got %d bytes, need more than %d",
			alg.MLDSALevel, len(data), size)
	}
	return data[:size], data[size:], nil
}

// Prefix é o prefixo de M' da seção 2.2 do draft.
var Prefix = []byte("CompositeAlgorithmSignatures2025")

const MaxContextLength = 255

// MessageRepresentative devolve M' = Prefix || Label || len(ctx) || ctx || PH(M).
func MessageRepresentative(alg Algorithm, ctx, message []byte) ([]byte, error) {
	if len(ctx) > MaxContextLength {
		return nil, errors.Errorf("Composite ML-DSA context must be at most %d bytes, got %d",
			MaxContextLength, len(ctx))
	}
	digest, err := hashBytes(alg.Hash, message)
	if err != nil {
		return nil, err
	}
	return concat(Prefix, []byte(alg.Label), []byte{byte(len(ctx))}, ctx, digest), nil
}

func hashBytes(h crypto.Hash, message []byte) ([]byte, error) {
	switch h {
	case crypto.SHA256:
		sum := sha256.Sum256(message)
		return sum[:], nil
	case crypto.SHA384:
		sum := sha512.Sum384(message)
		return sum[:], nil
	case crypto.SHA512:
		sum := sha512.Sum512(message)
		return sum[:], nil
	default:
		return nil, errors.Errorf("Unsupported Composite ML-DSA hash function: %s", h)
	}
}

type PublicKey struct {
	Algorithm   Algorithm
	MLDSA       *mldsa.PublicKey
	Traditional *ecdsa.PublicKey
}

type PrivateKey struct {
	Algorithm   Algorithm
	MLDSA       *mldsa.PrivateKey
	Traditional *ecdsa.PrivateKey
}

var _ crypto.Signer = (*PrivateKey)(nil)

// SignerOpts passa o ctx da aplicação para Sign. Com opts nil, o ctx é vazio.
type SignerOpts struct {
	Context []byte
}

func (*SignerOpts) HashFunc() crypto.Hash {
	return 0
}

// ecPrivateKeyWithoutPublic é o ECPrivateKey da RFC 5915 sem o campo publicKey.
type ecPrivateKeyWithoutPublic struct {
	Version    int
	PrivateKey []byte
	NamedCurve asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
}

// GenerateKey gera uma chave ML-DSA e uma chave ECDSA novas.
func GenerateKey(alg Algorithm) (*PrivateKey, error) {
	params, err := mldsaParametersForLevel(alg.MLDSALevel)
	if err != nil {
		return nil, err
	}
	mldsaKey, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to generate the ML-DSA component key")
	}
	ecKey, err := ecdsa.GenerateKey(alg.Curve, rand.Reader)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to generate the ECDSA component key")
	}
	return &PrivateKey{Algorithm: alg, MLDSA: mldsaKey, Traditional: ecKey}, nil
}

func ParsePublicKey(alg Algorithm, data []byte) (*PublicKey, error) {
	mldsaPK, tradPK, err := DeserializePublicKey(alg, data)
	if err != nil {
		return nil, err
	}
	params, err := mldsaParametersForLevel(alg.MLDSALevel)
	if err != nil {
		return nil, err
	}
	mldsaKey, err := mldsa.NewPublicKey(params, mldsaPK)
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid ML-DSA component public key")
	}
	ecKey, err := ecdsa.ParseUncompressedPublicKey(alg.Curve, tradPK)
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid ECDSA component public key")
	}
	return &PublicKey{Algorithm: alg, MLDSA: mldsaKey, Traditional: ecKey}, nil
}

func (pk *PublicKey) Bytes() ([]byte, error) {
	tradPK, err := pk.Traditional.Bytes()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to encode the ECDSA component public key")
	}
	return SerializePublicKey(pk.MLDSA.Bytes(), tradPK), nil
}

func (pk *PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*PublicKey)
	return ok && pk.Algorithm.OID.Equal(other.Algorithm.OID) &&
		pk.MLDSA.Equal(other.MLDSA) && pk.Traditional.Equal(other.Traditional)
}

func ParsePrivateKey(alg Algorithm, data []byte) (*PrivateKey, error) {
	seed, tradSK, err := DeserializePrivateKey(data)
	if err != nil {
		return nil, err
	}
	params, err := mldsaParametersForLevel(alg.MLDSALevel)
	if err != nil {
		return nil, err
	}
	mldsaKey, err := mldsa.NewPrivateKey(params, seed)
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid ML-DSA component seed")
	}
	ecKey, err := x509.ParseECPrivateKey(tradSK)
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid ECDSA component private key")
	}
	if ecKey.Curve != alg.Curve {
		return nil, errors.Errorf("ECDSA component key is on %s, but %s requires %s",
			ecKey.Curve.Params().Name, alg.Label, alg.Curve.Params().Name)
	}
	return &PrivateKey{Algorithm: alg, MLDSA: mldsaKey, Traditional: ecKey}, nil
}

func (sk *PrivateKey) Bytes() ([]byte, error) {
	scalar, err := sk.Traditional.Bytes()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to encode the ECDSA component private key")
	}
	tradSK, err := asn1.Marshal(ecPrivateKeyWithoutPublic{Version: 1, PrivateKey: scalar, NamedCurve: sk.Algorithm.CurveOID})
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to encode the ECDSA component private key")
	}
	return SerializePrivateKey(sk.MLDSA.Bytes(), tradSK), nil
}

func (sk *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{Algorithm: sk.Algorithm, MLDSA: sk.MLDSA.PublicKey(), Traditional: &sk.Traditional.PublicKey}
}

func (sk *PrivateKey) Public() crypto.PublicKey {
	return sk.PublicKey()
}

// Sign assina a mensagem inteira, não um digest.
func (sk *PrivateKey) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	var ctx []byte
	if o, ok := opts.(*SignerOpts); ok && o != nil {
		ctx = o.Context
	} else if opts != nil && opts.HashFunc() != 0 {
		return nil, errors.Errorf("Composite ML-DSA signs the whole message, not a %s digest", opts.HashFunc())
	}
	if random == nil {
		random = rand.Reader
	}

	mprime, err := MessageRepresentative(sk.Algorithm, ctx, message)
	if err != nil {
		return nil, err
	}
	// O ML-DSA recebe o Label como contexto. O ctx da aplicação já está em M'.
	mldsaSig, err := sk.MLDSA.Sign(nil, mprime, &mldsa.Options{Context: sk.Algorithm.Label})
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to compute the ML-DSA component signature")
	}
	digest, err := hashBytes(sk.Algorithm.TraditionalHash, mprime)
	if err != nil {
		return nil, err
	}
	tradSig, err := ecdsa.SignASN1(random, sk.Traditional, digest)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to compute the ECDSA component signature")
	}
	return SerializeSignatureValue(mldsaSig, tradSig), nil
}

// Verify só aceita a assinatura quando os dois componentes são válidos.
func Verify(pk *PublicKey, message, signature, ctx []byte) error {
	mprime, err := MessageRepresentative(pk.Algorithm, ctx, message)
	if err != nil {
		return err
	}
	mldsaSig, tradSig, err := DeserializeSignatureValue(pk.Algorithm, signature)
	if err != nil {
		return err
	}
	if err := mldsa.Verify(pk.MLDSA, mprime, mldsaSig, &mldsa.Options{Context: pk.Algorithm.Label}); err != nil {
		return errors.WithMessage(err, "Composite ML-DSA signature is invalid: ML-DSA component")
	}
	digest, err := hashBytes(pk.Algorithm.TraditionalHash, mprime)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(pk.Traditional, digest, tradSig) {
		return errors.New("Composite ML-DSA signature is invalid: ECDSA component")
	}
	return nil
}

func concat(parts ...[]byte) []byte {
	size := 0
	for _, p := range parts {
		size += len(p)
	}
	out := make([]byte, 0, size)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
