/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package middleware

import (
	"net/http"
)

type requireCert struct {
	next http.Handler
	// handshakeVerified accepts PeerCertificates in place of VerifiedChains.
	handshakeVerified bool
}

// RequireCert is used to ensure that a verified TLS client certificate was
// used for authentication.
func RequireCert() Middleware {
	return func(next http.Handler) http.Handler {
		return &requireCert{next: next}
	}
}

// RequireHandshakeVerifiedCert is RequireCert for a TLS server that verifies every client
// certificate during the handshake without recording VerifiedChains, as one configured by
// pkixext.ConfigureServerVerification: a presented certificate is enough.
func RequireHandshakeVerifiedCert() Middleware {
	return func(next http.Handler) http.Handler {
		return &requireCert{next: next, handshakeVerified: true}
	}
}

func (r *requireCert) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch {
	case req.TLS == nil:
		fallthrough
	case r.handshakeVerified && len(req.TLS.PeerCertificates) == 0:
		fallthrough
	case !r.handshakeVerified && len(req.TLS.VerifiedChains) == 0:
		fallthrough
	case !r.handshakeVerified && len(req.TLS.VerifiedChains[0]) == 0:
		logger.Warnw("Client request not authorized, client must pass a valid client certificate for this operation", "URL", req.URL, "Method", req.Method, "RemoteAddr", req.RemoteAddr)
		w.WriteHeader(http.StatusUnauthorized)
	default:
		r.next.ServeHTTP(w, req)
	}
}
