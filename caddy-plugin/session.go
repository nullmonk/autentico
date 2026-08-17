package caddy_plugin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// Session represents the data we store in the secure cookie
type Session struct {
	AccessToken string                 `json:"access_token"`
	Claims      map[string]interface{} `json:"claims"`
	ServerName  string                 `json:"server_name"`
	ExpiresAt   int64                  `json:"exp"`
}

// sign generates a signature for the given payload using HMAC-SHA256
func sign(payload []byte, secret string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	return h.Sum(nil)
}

// encodeAndSignSession serializes the session to JSON, signs it with the client secret,
// and returns a base64 string formatted as "payload.signature".
func encodeAndSignSession(sess *Session, secret string) (string, error) {
	payloadJSON, err := json.Marshal(sess)
	if err != nil {
		return "", err
	}

	signature := sign(payloadJSON, secret)

	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	return fmt.Sprintf("%s.%s", encodedPayload, encodedSignature), nil
}

// decodeAndVerifySession parses the "payload.signature" string, verifies the HMAC,
// checks expiration, and unmarshals the Session. It also ensures the ServerName matches.
func decodeAndVerifySession(cookieValue string, secret string, expectedServer string) (*Session, error) {
	// 1. Split payload and signature
	parts := splitString(cookieValue, '.')
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid session cookie format")
	}

	encodedPayload := parts[0]
	encodedSignature := parts[1]

	// 2. Decode payload and signature
	payloadJSON, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload")
	}

	providedSig, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature")
	}

	// 3. Verify Signature
	expectedSig := sign(payloadJSON, secret)
	if !hmac.Equal(providedSig, expectedSig) {
		return nil, fmt.Errorf("invalid session signature")
	}

	// 4. Unmarshal
	var sess Session
	if err := json.Unmarshal(payloadJSON, &sess); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session")
	}

	// 5. Check Expiration
	if time.Now().Unix() > sess.ExpiresAt {
		return nil, fmt.Errorf("session expired")
	}

	// 6. Verify ServerName matches
	if sess.ServerName != expectedServer {
		return nil, fmt.Errorf("session server mismatch: expected %s, got %s", expectedServer, sess.ServerName)
	}

	return &sess, nil
}

func splitString(s string, sep rune) []string {
	var res []string
	var curr string
	for _, char := range s {
		if char == sep {
			res = append(res, curr)
			curr = ""
		} else {
			curr += string(char)
		}
	}
	res = append(res, curr)
	return res
}
