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

	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/pkg/errors"
)

// Algorithm describes a composite pair: the ML-DSA pairs of draft-ietf-lamps-pq-composite-sigs-19,
// and experimental SLH-DSA pairs built the same way.
type Algorithm struct {
	OID   asn1.ObjectIdentifier
	Label string
	// MLDSALevel is 44, 65 or 87 for an ML-DSA pair and 0 for any other.
	MLDSALevel int
	PQ         PQComponent
	// Hash is the PH that digests the message inside M'.
	Hash     crypto.Hash
	Curve    elliptic.Curve
	CurveOID asn1.ObjectIdentifier
	// TraditionalHash is the hash ECDSA applies to M'. In the P-384 pairs it differs from Hash.
	TraditionalHash crypto.Hash
}

var (
	OIDMLDSA44ECDSAP256SHA256 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 40}
	OIDMLDSA65ECDSAP384SHA512 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 46}
	OIDMLDSA87ECDSAP384SHA512 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 49}

	OIDSLHDSASHA2128sECDSAP256SHA256 = oidExperimental(1)
	OIDSLHDSASHA2128fECDSAP256SHA256 = oidExperimental(2)
	OIDSLHDSASHA2192sECDSAP384SHA512 = oidExperimental(3)
	OIDSLHDSASHA2192fECDSAP384SHA512 = oidExperimental(4)
	OIDSLHDSASHA2256sECDSAP384SHA512 = oidExperimental(5)
	OIDSLHDSASHA2256fECDSAP384SHA512 = oidExperimental(6)

	oidCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
)

// oidExperimentalArc is 1.3.6.1.4.1.32473, the enterprise number RFC 5612 reserves for
// documentation and examples, followed by 1 for the composite SLH-DSA pairs. These OIDs are for
// this testbed only. A 2.25 UUID arc cannot be used: encoding/asn1 rejects arcs above 2^31-1.
var oidExperimentalArc = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1}

func oidExperimental(arc int) asn1.ObjectIdentifier {
	return append(append(asn1.ObjectIdentifier(nil), oidExperimentalArc...), arc)
}

var algorithms = []Algorithm{
	{
		OID:             OIDMLDSA44ECDSAP256SHA256,
		Label:           "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
		MLDSALevel:      44,
		PQ:              mldsaComponent{level: 44},
		Hash:            crypto.SHA256,
		Curve:           elliptic.P256(),
		CurveOID:        oidCurveP256,
		TraditionalHash: crypto.SHA256,
	},
	{
		OID:             OIDMLDSA65ECDSAP384SHA512,
		Label:           "COMPSIG-MLDSA65-ECDSA-P384-SHA512",
		MLDSALevel:      65,
		PQ:              mldsaComponent{level: 65},
		Hash:            crypto.SHA512,
		Curve:           elliptic.P384(),
		CurveOID:        oidCurveP384,
		TraditionalHash: crypto.SHA384,
	},
	{
		OID:             OIDMLDSA87ECDSAP384SHA512,
		Label:           "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
		MLDSALevel:      87,
		PQ:              mldsaComponent{level: 87},
		Hash:            crypto.SHA512,
		Curve:           elliptic.P384(),
		CurveOID:        oidCurveP384,
		TraditionalHash: crypto.SHA384,
	},
	{
		OID:             OIDSLHDSASHA2128sECDSAP256SHA256,
		Label:           "COMPSIG-SLHDSA-SHA2-128S-ECDSA-P256-SHA256",
		PQ:              slhdsaComponent{params: slhdsa.SHA2_128s},
		Hash:            crypto.SHA256,
		Curve:           elliptic.P256(),
		CurveOID:        oidCurveP256,
		TraditionalHash: crypto.SHA256,
	},
	{
		OID:             OIDSLHDSASHA2128fECDSAP256SHA256,
		Label:           "COMPSIG-SLHDSA-SHA2-128F-ECDSA-P256-SHA256",
		PQ:              slhdsaComponent{params: slhdsa.SHA2_128f},
		Hash:            crypto.SHA256,
		Curve:           elliptic.P256(),
		CurveOID:        oidCurveP256,
		TraditionalHash: crypto.SHA256,
	},
	{
		OID:             OIDSLHDSASHA2192sECDSAP384SHA512,
		Label:           "COMPSIG-SLHDSA-SHA2-192S-ECDSA-P384-SHA512",
		PQ:              slhdsaComponent{params: slhdsa.SHA2_192s},
		Hash:            crypto.SHA512,
		Curve:           elliptic.P384(),
		CurveOID:        oidCurveP384,
		TraditionalHash: crypto.SHA384,
	},
	{
		OID:             OIDSLHDSASHA2192fECDSAP384SHA512,
		Label:           "COMPSIG-SLHDSA-SHA2-192F-ECDSA-P384-SHA512",
		PQ:              slhdsaComponent{params: slhdsa.SHA2_192f},
		Hash:            crypto.SHA512,
		Curve:           elliptic.P384(),
		CurveOID:        oidCurveP384,
		TraditionalHash: crypto.SHA384,
	},
	{
		OID:             OIDSLHDSASHA2256sECDSAP384SHA512,
		Label:           "COMPSIG-SLHDSA-SHA2-256S-ECDSA-P384-SHA512",
		PQ:              slhdsaComponent{params: slhdsa.SHA2_256s},
		Hash:            crypto.SHA512,
		Curve:           elliptic.P384(),
		CurveOID:        oidCurveP384,
		TraditionalHash: crypto.SHA384,
	},
	{
		OID:             OIDSLHDSASHA2256fECDSAP384SHA512,
		Label:           "COMPSIG-SLHDSA-SHA2-256F-ECDSA-P384-SHA512",
		PQ:              slhdsaComponent{params: slhdsa.SHA2_256f},
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
		if alg.MLDSALevel != 0 && alg.MLDSALevel == level {
			return alg, nil
		}
	}
	return Algorithm{}, errors.Errorf("Invalid MLDSA key size for Composite ML-DSA: %d (expecting 44, 65 or 87)", level)
}

// AlgorithmForSLHDSA returns the experimental composite pair of the SLH-DSA parameter set. Only
// the six SHA2 sets have a pair.
func AlgorithmForSLHDSA(ps slhdsa.ParameterSet) (Algorithm, error) {
	for _, alg := range algorithms {
		if c, ok := alg.PQ.(slhdsaComponent); ok && c.params.OID.Equal(ps.OID) {
			return alg, nil
		}
	}
	return Algorithm{}, errors.Errorf("No composite pair for %s", ps.Name)
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

// DeserializePublicKey splits the public key at the fixed size of the post-quantum component. The
// size of the traditional part is not checked.
func DeserializePublicKey(alg Algorithm, data []byte) (pqPK, tradPK []byte, err error) {
	size := alg.PQ.PublicKeySize()
	if len(data) <= size {
		return nil, nil, errors.Errorf("Composite public key too short for %s: got %d bytes, need more than %d",
			alg.PQ.Name(), len(data), size)
	}
	return data[:size], data[size:], nil
}

// SerializePrivateKey concatena a seed ML-DSA de 32 bytes e a chave privada clássica.
func SerializePrivateKey(mldsaSeed, tradSK []byte) []byte {
	return concat(mldsaSeed, tradSK)
}

// DeserializePrivateKey splits the private key of an ML-DSA pair after the 32-byte seed.
func DeserializePrivateKey(data []byte) (mldsaSeed, tradSK []byte, err error) {
	return splitPrivateKey(mldsa.PrivateKeySize, data)
}

func splitPrivateKey(size int, data []byte) (pqSK, tradSK []byte, err error) {
	if len(data) <= size {
		return nil, nil, errors.Errorf("Composite private key too short: got %d bytes, need more than %d",
			len(data), size)
	}
	return data[:size], data[size:], nil
}

func SerializeSignatureValue(mldsaSig, tradSig []byte) []byte {
	return concat(mldsaSig, tradSig)
}

// DeserializeSignatureValue splits the signature at the fixed size of the post-quantum signature.
// The rest is the DER ECDSA signature.
func DeserializeSignatureValue(alg Algorithm, data []byte) (pqSig, tradSig []byte, err error) {
	size := alg.PQ.SignatureSize()
	if len(data) <= size {
		return nil, nil, errors.Errorf("Composite signature too short for %s: got %d bytes, need more than %d",
			alg.PQ.Name(), len(data), size)
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

// PublicKey holds the post-quantum component in MLDSA or in SLHDSA, according to Algorithm.PQ; the
// other field is nil.
type PublicKey struct {
	Algorithm   Algorithm
	MLDSA       *mldsa.PublicKey
	SLHDSA      *slhdsa.PublicKey
	Traditional *ecdsa.PublicKey
}

// PrivateKey holds the post-quantum component in MLDSA or in SLHDSA, according to Algorithm.PQ; the
// other field is nil.
type PrivateKey struct {
	Algorithm   Algorithm
	MLDSA       *mldsa.PrivateKey
	SLHDSA      *slhdsa.PrivateKey
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

// newPublicKey stores pq in the field matching its type. A type of no known component leaves both
// fields nil, which every later operation rejects.
func newPublicKey(alg Algorithm, pq crypto.PublicKey, trad *ecdsa.PublicKey) *PublicKey {
	pk := &PublicKey{Algorithm: alg, Traditional: trad}
	switch k := pq.(type) {
	case *mldsa.PublicKey:
		pk.MLDSA = k
	case *slhdsa.PublicKey:
		pk.SLHDSA = k
	}
	return pk
}

func newPrivateKey(alg Algorithm, pq crypto.Signer, trad *ecdsa.PrivateKey) *PrivateKey {
	sk := &PrivateKey{Algorithm: alg, Traditional: trad}
	switch k := pq.(type) {
	case *mldsa.PrivateKey:
		sk.MLDSA = k
	case *slhdsa.PrivateKey:
		sk.SLHDSA = k
	}
	return sk
}

// pq returns the post-quantum component as an untyped nil when neither field is set, so the
// component's type check rejects it.
func (pk *PublicKey) pq() crypto.PublicKey {
	switch {
	case pk.MLDSA != nil:
		return pk.MLDSA
	case pk.SLHDSA != nil:
		return pk.SLHDSA
	}
	return nil
}

func (sk *PrivateKey) pq() crypto.Signer {
	switch {
	case sk.MLDSA != nil:
		return sk.MLDSA
	case sk.SLHDSA != nil:
		return sk.SLHDSA
	}
	return nil
}

// GenerateKey generates fresh post-quantum and ECDSA component keys.
func GenerateKey(alg Algorithm) (*PrivateKey, error) {
	pqKey, err := alg.PQ.GenerateKey()
	if err != nil {
		return nil, errors.WithMessagef(err, "Failed to generate the %s component key", alg.PQ.Family())
	}
	ecKey, err := ecdsa.GenerateKey(alg.Curve, rand.Reader)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to generate the ECDSA component key")
	}
	return newPrivateKey(alg, pqKey, ecKey), nil
}

func ParsePublicKey(alg Algorithm, data []byte) (*PublicKey, error) {
	pqPK, tradPK, err := DeserializePublicKey(alg, data)
	if err != nil {
		return nil, err
	}
	pqKey, err := alg.PQ.ParsePublicKey(pqPK)
	if err != nil {
		return nil, errors.WithMessagef(err, "Invalid %s component public key", alg.PQ.Family())
	}
	ecKey, err := ecdsa.ParseUncompressedPublicKey(alg.Curve, tradPK)
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid ECDSA component public key")
	}
	return newPublicKey(alg, pqKey, ecKey), nil
}

func (pk *PublicKey) Bytes() ([]byte, error) {
	pqPK, err := pk.Algorithm.PQ.PublicKeyBytes(pk.pq())
	if err != nil {
		return nil, err
	}
	tradPK, err := pk.Traditional.Bytes()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to encode the ECDSA component public key")
	}
	return SerializePublicKey(pqPK, tradPK), nil
}

func (pk *PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*PublicKey)
	if !ok || !pk.Algorithm.OID.Equal(other.Algorithm.OID) || !pk.Traditional.Equal(other.Traditional) {
		return false
	}
	a, ok := pk.pq().(interface{ Equal(crypto.PublicKey) bool })
	return ok && other.pq() != nil && a.Equal(other.pq())
}

func ParsePrivateKey(alg Algorithm, data []byte) (*PrivateKey, error) {
	pqSK, tradSK, err := splitPrivateKey(alg.PQ.PrivateKeySize(), data)
	if err != nil {
		return nil, err
	}
	pqKey, err := alg.PQ.ParsePrivateKey(pqSK)
	if err != nil {
		return nil, errors.WithMessagef(err, "Invalid %s component private key", alg.PQ.Family())
	}
	ecKey, err := x509.ParseECPrivateKey(tradSK)
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid ECDSA component private key")
	}
	if ecKey.Curve != alg.Curve {
		return nil, errors.Errorf("ECDSA component key is on %s, but %s requires %s",
			ecKey.Curve.Params().Name, alg.Label, alg.Curve.Params().Name)
	}
	return newPrivateKey(alg, pqKey, ecKey), nil
}

// Bytes returns the raw post-quantum private key followed by the ECPrivateKey without its
// publicKey field.
func (sk *PrivateKey) Bytes() ([]byte, error) {
	pqSK, err := sk.Algorithm.PQ.PrivateKeyBytes(sk.pq())
	if err != nil {
		return nil, err
	}
	scalar, err := sk.Traditional.Bytes()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to encode the ECDSA component private key")
	}
	tradSK, err := asn1.Marshal(ecPrivateKeyWithoutPublic{Version: 1, PrivateKey: scalar, NamedCurve: sk.Algorithm.CurveOID})
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to encode the ECDSA component private key")
	}
	return SerializePrivateKey(pqSK, tradSK), nil
}

func (sk *PrivateKey) PublicKey() *PublicKey {
	var pqPub crypto.PublicKey
	if pq := sk.pq(); pq != nil {
		pqPub = pq.Public()
	}
	return newPublicKey(sk.Algorithm, pqPub, &sk.Traditional.PublicKey)
}

func (sk *PrivateKey) Public() crypto.PublicKey {
	return sk.PublicKey()
}

// Sign signs the whole message, not a digest. The post-quantum component receives the Label as its
// context; the application ctx is already inside M'.
func (sk *PrivateKey) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	var ctx []byte
	if o, ok := opts.(*SignerOpts); ok && o != nil {
		ctx = o.Context
	} else if opts != nil && opts.HashFunc() != 0 {
		return nil, errors.Errorf("Composite %s signs the whole message, not a %s digest", sk.Algorithm.PQ.Family(), opts.HashFunc())
	}
	if random == nil {
		random = rand.Reader
	}

	mprime, err := MessageRepresentative(sk.Algorithm, ctx, message)
	if err != nil {
		return nil, err
	}
	pqSig, err := sk.Algorithm.PQ.Sign(sk.pq(), mprime, []byte(sk.Algorithm.Label))
	if err != nil {
		return nil, errors.WithMessagef(err, "Failed to compute the %s component signature", sk.Algorithm.PQ.Family())
	}
	digest, err := hashBytes(sk.Algorithm.TraditionalHash, mprime)
	if err != nil {
		return nil, err
	}
	tradSig, err := ecdsa.SignASN1(random, sk.Traditional, digest)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to compute the ECDSA component signature")
	}
	return SerializeSignatureValue(pqSig, tradSig), nil
}

// Verify accepts the signature only when both components are valid.
func Verify(pk *PublicKey, message, signature, ctx []byte) error {
	mprime, err := MessageRepresentative(pk.Algorithm, ctx, message)
	if err != nil {
		return err
	}
	pqSig, tradSig, err := DeserializeSignatureValue(pk.Algorithm, signature)
	if err != nil {
		return err
	}
	family := pk.Algorithm.PQ.Family()
	if err := pk.Algorithm.PQ.Verify(pk.pq(), mprime, pqSig, []byte(pk.Algorithm.Label)); err != nil {
		return errors.WithMessagef(err, "Composite %s signature is invalid: %s component", family, family)
	}
	digest, err := hashBytes(pk.Algorithm.TraditionalHash, mprime)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(pk.Traditional, digest, tradSig) {
		return errors.Errorf("Composite %s signature is invalid: ECDSA component", family)
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
