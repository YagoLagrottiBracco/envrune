package cloud

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifyWebhookChecksTheSignature(t *testing.T) {
	secret := hex.EncodeToString(make([]byte, 32))
	body := []byte(`{"action":"member.removed"}`)
	mac := hmac.New(sha256.New, make([]byte, 32))
	mac.Write(body)
	header := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !VerifyWebhook(secret, header, body) {
		t.Fatal("a valid signature did not verify")
	}
	if VerifyWebhook(secret, header, []byte(`{"action":"member.added"}`)) || VerifyWebhook("ff"+secret[2:], header, body) || VerifyWebhook("not hex", header, body) {
		t.Fatal("another body, another secret, or a malformed secret verified")
	}
}
