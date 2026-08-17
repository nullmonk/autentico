package caddy_plugin

import (
	"testing"
	"time"
)

func TestSessionSignAndVerify(t *testing.T) {
	secret := "super_secret_key"
	sess := &Session{
		AccessToken: "test_token",
		Claims:      map[string]interface{}{"role": "admin"},
		ServerName:  "default",
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
	}

	encoded, err := encodeAndSignSession(sess, secret)
	if err != nil {
		t.Fatalf("Failed to encode session: %v", err)
	}

	decoded, err := decodeAndVerifySession(encoded, secret, "default")
	if err != nil {
		t.Fatalf("Failed to decode session: %v", err)
	}

	if decoded.AccessToken != sess.AccessToken {
		t.Errorf("Expected %s, got %s", sess.AccessToken, decoded.AccessToken)
	}
}

func TestSessionVerifyTampered(t *testing.T) {
	secret := "super_secret_key"
	sess := &Session{
		AccessToken: "test_token",
		Claims:      map[string]interface{}{"role": "user"},
		ServerName:  "default",
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
	}

	encoded, _ := encodeAndSignSession(sess, secret)
	parts := splitString(encoded, '.')

	// Tamper payload
	sess.Claims["role"] = "admin"
	tamperedPayload, _ := encodeAndSignSession(sess, "different_secret")
	tamperedParts := splitString(tamperedPayload, '.')

	tamperedEncoded := tamperedParts[0] + "." + parts[1] // Original signature

	_, err := decodeAndVerifySession(tamperedEncoded, secret, "default")
	if err == nil {
		t.Errorf("Expected error on tampered session, got nil")
	}
}

func TestSessionVerifyServerMismatch(t *testing.T) {
	secret := "super_secret_key"
	sess := &Session{
		AccessToken: "test_token",
		Claims:      map[string]interface{}{"role": "admin"},
		ServerName:  "default",
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
	}

	encoded, err := encodeAndSignSession(sess, secret)
	if err != nil {
		t.Fatalf("Failed to encode session: %v", err)
	}

	_, err = decodeAndVerifySession(encoded, secret, "other_server")
	if err == nil {
		t.Fatalf("Expected error for mismatched server, got nil")
	}
}
