package cloudcrypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// vectorsPath holds signed messages produced by this package, which the
// server (cloud/web) checks with its own implementation, so the two
// encodings cannot drift apart. Regenerate with ENVRUNE_WRITE_VECTORS=1.
var vectorsPath = filepath.Join("..", "..", "cloud", "web", "src", "lib", "crypto-vectors.json")

type vector struct {
	Kind      string         `json:"kind"`
	Fields    map[string]any `json:"fields"`
	PublicKey string         `json:"public_key"`
	Message   string         `json:"message"`
	Signature string         `json:"signature"`
}

func TestCrossLanguageVectors(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	account := &Account{UserID: "00000000-0000-0000-0000-00000000000a", Public: private.Public().(ed25519.PublicKey), private: private}
	at := time.Unix(1790000000, 123456789)

	member := &MembershipCertificate{OrgID: "11111111-1111-1111-1111-111111111111", UserID: "00000000-0000-0000-0000-00000000000b",
		AccountKey: bytes.Repeat([]byte{2}, 32), Role: RoleAdmin, Scope: []string{"shop/*", "billing/production"}, IssuedAt: at, IssuerID: account.UserID}
	member.Signature = account.sign(member.signed())

	device := &RecipientCertificate{Kind: KindDevice, UserID: account.UserID, RecipientID: "laptop",
		AgeRecipient: "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq", SigningKey: bytes.Repeat([]byte{3}, 32), CreatedAt: at}
	device.Signature = account.sign(device.signed())

	machine := &RecipientCertificate{Kind: KindMachine, UserID: account.UserID, RecipientID: "tok123",
		AgeRecipient: device.AgeRecipient, Scope: []string{"shop/production"}, CreatedAt: at}
	machine.Signature = account.sign(machine.signed())

	b64 := base64.StdEncoding.EncodeToString
	vectors := []vector{
		{Kind: "member", PublicKey: b64(account.Public), Message: b64(member.signed()), Signature: b64(member.Signature), Fields: map[string]any{
			"org_id": member.OrgID, "user_id": member.UserID, "account_key": b64(member.AccountKey), "role": member.Role,
			"scope": member.Scope, "issued_at_us": at.UnixMicro(), "issuer_id": member.IssuerID}},
		{Kind: "recipient", PublicKey: b64(account.Public), Message: b64(device.signed()), Signature: b64(device.Signature), Fields: map[string]any{
			"kind": device.Kind, "user_id": device.UserID, "recipient_id": device.RecipientID, "age_recipient": device.AgeRecipient,
			"signing_key": b64(device.SigningKey), "scope": []string{}, "created_at_us": at.UnixMicro()}},
		{Kind: "recipient", PublicKey: b64(account.Public), Message: b64(machine.signed()), Signature: b64(machine.Signature), Fields: map[string]any{
			"kind": machine.Kind, "user_id": machine.UserID, "recipient_id": machine.RecipientID, "age_recipient": machine.AgeRecipient,
			"signing_key": "", "scope": machine.Scope, "created_at_us": at.UnixMicro()}},
		// The hash the server stores for a machine token's secret.
		{Kind: "token-secret", Message: b64(HashTokenSecret(bytes.Repeat([]byte{5}, 32))), Fields: map[string]any{
			"secret": b64(bytes.Repeat([]byte{5}, 32))}},
	}
	got, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("ENVRUNE_WRITE_VECTORS") != "" {
		if err := os.WriteFile(vectorsPath, got, 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Skipf("no vectors file (%v); regenerate with ENVRUNE_WRITE_VECTORS=1", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
		t.Fatal("the signed-message encoding changed; regenerate the vectors with ENVRUNE_WRITE_VECTORS=1 and update cloud/web")
	}
}
