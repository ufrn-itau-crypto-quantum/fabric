/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bccsp

// ML-DSA (FIPS 204) options.
//
// Key generation has one option per parameter set, since the security category is chosen at
// generation time. Importation has one option per encoding: the parameter set comes from the
// algorithm OID inside PKCS#8 and SPKI.

// MLDSA44KeyGenOpts contains options for ML-DSA-44 key generation.
type MLDSA44KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *MLDSA44KeyGenOpts) Algorithm() string {
	return MLDSA44
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MLDSA44KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// MLDSA65KeyGenOpts contains options for ML-DSA-65 key generation.
type MLDSA65KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *MLDSA65KeyGenOpts) Algorithm() string {
	return MLDSA65
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MLDSA65KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// MLDSA87KeyGenOpts contains options for ML-DSA-87 key generation.
type MLDSA87KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *MLDSA87KeyGenOpts) Algorithm() string {
	return MLDSA87
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MLDSA87KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// MLDSAPrivateKeyImportOpts contains options for ML-DSA private key importation
// from PKCS#8 DER. The parameter set is taken from the encoding.
type MLDSAPrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *MLDSAPrivateKeyImportOpts) Algorithm() string {
	return MLDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MLDSAPrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// MLDSAPKIXPublicKeyImportOpts contains options for ML-DSA public key importation
// in PKIX format. The parameter set is taken from the encoding.
type MLDSAPKIXPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *MLDSAPKIXPublicKeyImportOpts) Algorithm() string {
	return MLDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MLDSAPKIXPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// MLDSAGoPublicKeyImportOpts contains options for ML-DSA key importation
// from an *mldsa.PublicKey.
type MLDSAGoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *MLDSAGoPublicKeyImportOpts) Algorithm() string {
	return MLDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MLDSAGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}
