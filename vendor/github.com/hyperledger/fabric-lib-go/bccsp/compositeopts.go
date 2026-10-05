/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bccsp

import "encoding/asn1"

// CompositeMLDSA é o Composite ML-DSA do draft ietf lamps pq composite sigs 19; o par vem do OID.
const CompositeMLDSA = "COMPOSITE_MLDSA"

// CompositeKeyGenOpts escolhe o par composite pelo OID, por exemplo composite.OIDMLDSA65ECDSAP384SHA512.
type CompositeKeyGenOpts struct {
	OID       asn1.ObjectIdentifier
	Temporary bool
}

func (opts *CompositeKeyGenOpts) Algorithm() string {
	return CompositeMLDSA
}

func (opts *CompositeKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// CompositePrivateKeyImportOpts importa uma chave privada composite em PKCS#8 DER.
type CompositePrivateKeyImportOpts struct {
	Temporary bool
}

func (opts *CompositePrivateKeyImportOpts) Algorithm() string {
	return CompositeMLDSA
}

func (opts *CompositePrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// CompositePKIXPublicKeyImportOpts importa uma chave pública composite em SubjectPublicKeyInfo DER.
type CompositePKIXPublicKeyImportOpts struct {
	Temporary bool
}

func (opts *CompositePKIXPublicKeyImportOpts) Algorithm() string {
	return CompositeMLDSA
}

func (opts *CompositePKIXPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// CompositeGoPublicKeyImportOpts importa um *composite.PublicKey.
type CompositeGoPublicKeyImportOpts struct {
	Temporary bool
}

func (opts *CompositeGoPublicKeyImportOpts) Algorithm() string {
	return CompositeMLDSA
}

func (opts *CompositeGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}
