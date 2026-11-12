/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bccsp

import "encoding/asn1"

// SLHDSA is pure SLH-DSA (FIPS 205) with the parameter set carried by the RFC 9909 OID.
const SLHDSA = "SLHDSA"

// SLHDSAKeyGenOpts picks the parameter set by its pure SLH-DSA OID, for example
// slhdsa.SHA2_128s.OID.
type SLHDSAKeyGenOpts struct {
	OID       asn1.ObjectIdentifier
	Temporary bool
}

func (opts *SLHDSAKeyGenOpts) Algorithm() string {
	return SLHDSA
}

func (opts *SLHDSAKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// SLHDSAPrivateKeyImportOpts imports an SLH-DSA private key from PKCS#8 DER.
type SLHDSAPrivateKeyImportOpts struct {
	Temporary bool
}

func (opts *SLHDSAPrivateKeyImportOpts) Algorithm() string {
	return SLHDSA
}

func (opts *SLHDSAPrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// SLHDSAPKIXPublicKeyImportOpts imports an SLH-DSA public key from SubjectPublicKeyInfo DER.
type SLHDSAPKIXPublicKeyImportOpts struct {
	Temporary bool
}

func (opts *SLHDSAPKIXPublicKeyImportOpts) Algorithm() string {
	return SLHDSA
}

func (opts *SLHDSAPKIXPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// SLHDSAGoPublicKeyImportOpts imports an *slhdsa.PublicKey.
type SLHDSAGoPublicKeyImportOpts struct {
	Temporary bool
}

func (opts *SLHDSAGoPublicKeyImportOpts) Algorithm() string {
	return SLHDSA
}

func (opts *SLHDSAGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}
