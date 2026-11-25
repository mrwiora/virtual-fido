package identities

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/bulwarkid/virtual-fido/webauthn"
)

func newTestIdentity(vault *IdentityVault) *CredentialSource {
	return vault.NewIdentity(
		&webauthn.PublicKeyCredentialRPEntity{ID: "example.com", Name: "Example"},
		&webauthn.PublicKeyCrendentialUserEntity{ID: []byte{1, 2, 3}, Name: "alice", DisplayName: "Alice"},
	)
}

func TestNewIdentityHasHMACSecret(t *testing.T) {
	source := newTestIdentity(NewIdentityVault())
	if source.HMACSecret == nil {
		t.Fatal("new credential has no hmac-secret values")
	}
	withUV, withoutUV := source.HMACSecret.CredRandomWithUV, source.HMACSecret.CredRandomWithoutUV
	if len(withUV) != 32 || len(withoutUV) != 32 {
		t.Fatalf("unexpected CredRandom lengths %d/%d", len(withUV), len(withoutUV))
	}
	if bytes.Equal(withUV, withoutUV) {
		t.Fatal("CredRandomWithUV and CredRandomWithoutUV must differ")
	}
}

func TestHMACSecretSurvivesSaveAndLoad(t *testing.T) {
	vault := NewIdentityVault()
	original := newTestIdentity(vault)

	state := FIDODeviceConfig{Sources: vault.Export()}
	encrypted, err := EncryptFIDOState(state, "passphrase")
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptFIDOState(encrypted, "passphrase")
	if err != nil {
		t.Fatal(err)
	}
	loaded := NewIdentityVault()
	if err := loaded.Import(decrypted.Sources); err != nil {
		t.Fatal(err)
	}
	restored := loaded.CredentialSources[0]
	if restored.HMACSecret == nil ||
		!bytes.Equal(restored.HMACSecret.CredRandomWithUV, original.HMACSecret.CredRandomWithUV) ||
		!bytes.Equal(restored.HMACSecret.CredRandomWithoutUV, original.HMACSecret.CredRandomWithoutUV) {
		t.Fatal("hmac-secret values changed across save and load")
	}
}

func TestLegacyCredentialHasNoHMACSecret(t *testing.T) {
	vault := NewIdentityVault()
	newTestIdentity(vault)
	saved := vault.Export()
	saved[0].CredRandomWithUV = nil
	saved[0].CredRandomWithoutUV = nil

	data, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("cred_random")) {
		t.Fatal("legacy credential should not serialize hmac-secret fields")
	}
	var decoded []SavedCredentialSource
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	loaded := NewIdentityVault()
	if err := loaded.Import(decoded); err != nil {
		t.Fatal(err)
	}
	if loaded.CredentialSources[0].HMACSecret != nil {
		t.Fatal("legacy credential should not get hmac-secret values on import")
	}
}
