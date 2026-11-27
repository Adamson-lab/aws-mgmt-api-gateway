package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

var (
	ErrMissingHeaders   = errors.New("missing X-Signature-256 or X-Timestamp header")
	ErrInvalidTimestamp = errors.New("invalid X-Timestamp header")
	ErrTimestampSkew    = errors.New("request timestamp outside allowed replay window")
	ErrInvalidSignature = errors.New("invalid HMAC-SHA256 signature")
)

type Verifier struct {
	secret      []byte
	maxSkew     time.Duration
	nowProvider func() time.Time
}

func NewVerifier(secret string, maxSkew time.Duration) *Verifier {
	if maxSkew <= 0 {
		maxSkew = 5 * time.Minute
	}
	return &Verifier{
		secret:      []byte(secret),
		maxSkew:     maxSkew,
		nowProvider: func() time.Time { return time.Now().UTC() },
	}
}

func ComputeSignature(secret []byte, timestampUnix int64, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = fmt.Fprintf(mac, "%d.", timestampUnix)
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (v *Verifier) Verify(signatureHeader, timestampHeader string, body []byte) error {
	if signatureHeader == "" || timestampHeader == "" {
		return ErrMissingHeaders
	}

	ts, err := strconv.ParseInt(strings.TrimSpace(timestampHeader), 10, 64)
	if err != nil {
		return ErrInvalidTimestamp
	}

	now := v.nowProvider().UTC().Unix()
	if math.Abs(float64(now-ts)) > v.maxSkew.Seconds() {
		return ErrTimestampSkew
	}

	expected := ComputeSignature(v.secret, ts, body)
	if !hmac.Equal([]byte(expected), []byte(strings.TrimSpace(signatureHeader))) {
		return ErrInvalidSignature
	}
	return nil
}
