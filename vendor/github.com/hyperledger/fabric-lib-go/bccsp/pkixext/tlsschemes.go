/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pkixext

import (
	"fmt"
	"slices"
	"strings"
	"sync"
)

// TLSScheme is a TLS 1.3 signature scheme that a package registered in crypto/tls. Registration
// needs the patched toolchain of blockchain/src/go-tlsext and the tlsext build tag.
type TLSScheme struct {
	Name      string
	Codepoint uint16
}

func (s TLSScheme) String() string {
	return fmt.Sprintf("%s(0x%04x)", s.Name, s.Codepoint)
}

var (
	tlsSchemesMu sync.Mutex
	tlsSchemes   []TLSScheme
)

// RecordTLSScheme records s as registered in crypto/tls, for TLSSchemes. Recording the same
// codepoint again replaces the previous entry.
func RecordTLSScheme(s TLSScheme) {
	tlsSchemesMu.Lock()
	defer tlsSchemesMu.Unlock()
	tlsSchemes = slices.DeleteFunc(tlsSchemes, func(r TLSScheme) bool { return r.Codepoint == s.Codepoint })
	tlsSchemes = append(tlsSchemes, s)
}

// TLSSchemes returns the recorded schemes ordered by codepoint. It is empty in a binary built
// without the tlsext tag, where no package registers schemes in crypto/tls.
func TLSSchemes() []TLSScheme {
	tlsSchemesMu.Lock()
	defer tlsSchemesMu.Unlock()
	schemes := slices.Clone(tlsSchemes)
	slices.SortFunc(schemes, func(a, b TLSScheme) int { return int(a.Codepoint) - int(b.Codepoint) })
	return schemes
}

// TLSSchemesLogPrefix starts the line that peer, orderer and fabric-ca log at startup with
// TLSSchemesLog. The runner searches the node logs for it, so it must not change.
const TLSSchemesLogPrefix = "Registered TLS signature schemes:"

// TLSSchemesLog returns TLSSchemesLogPrefix followed by the recorded schemes, or by "none".
func TLSSchemesLog() string {
	schemes := TLSSchemes()
	if len(schemes) == 0 {
		return TLSSchemesLogPrefix + " none"
	}
	names := make([]string, len(schemes))
	for i, s := range schemes {
		names[i] = s.String()
	}
	return TLSSchemesLogPrefix + " " + strings.Join(names, ", ")
}
