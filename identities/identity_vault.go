package identities

import (
	"bytes"
	"crypto/x509"
	"fmt"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/webauthn"
)

// HMACSecret holds the per-credential secrets of the CTAP2 hmac-secret
// extension, which backs WebAuthn PRF. Relying parties may use PRF outputs as
// encryption keys, so these values must never be lost or regenerated.
type HMACSecret struct {
	CredRandomWithUV    []byte
	CredRandomWithoutUV []byte
}

func NewHMACSecret() *HMACSecret {
	return &HMACSecret{
		CredRandomWithUV:    crypto.RandomBytes(32),
		CredRandomWithoutUV: crypto.RandomBytes(32),
	}
}

type CredentialSource struct {
	Type             string
	ID               []byte
	PrivateKey       *cose.SupportedCOSEPrivateKey
	RelyingParty     *webauthn.PublicKeyCredentialRPEntity
	User             *webauthn.PublicKeyCrendentialUserEntity
	SignatureCounter int32
	// HMACSecret is nil for credentials created before hmac-secret support.
	HMACSecret *HMACSecret
}

func (source *CredentialSource) CTAPDescriptor() webauthn.PublicKeyCredentialDescriptor {
	return webauthn.PublicKeyCredentialDescriptor{
		Type:       "public-key",
		ID:         source.ID,
		Transports: []string{},
	}
}

type IdentityVault struct {
	CredentialSources []*CredentialSource
}

func NewIdentityVault() *IdentityVault {
	sources := make([]*CredentialSource, 0)
	return &IdentityVault{CredentialSources: sources}
}

func (vault *IdentityVault) NewIdentity(relyingParty *webauthn.PublicKeyCredentialRPEntity, user *webauthn.PublicKeyCrendentialUserEntity) *CredentialSource {
	credentialID := crypto.RandomBytes(16)
	privateKey := crypto.GenerateECDSAKey()
	cosePrivateKey := &cose.SupportedCOSEPrivateKey{ECDSA: privateKey}
	credentialSource := CredentialSource{
		Type:             "public-key",
		ID:               credentialID,
		PrivateKey:       cosePrivateKey,
		RelyingParty:     relyingParty,
		User:             user,
		SignatureCounter: 0,
		HMACSecret:       NewHMACSecret(),
	}
	vault.AddIdentity(&credentialSource)
	return &credentialSource
}

func (vault *IdentityVault) AddIdentity(source *CredentialSource) {
	vault.CredentialSources = append(vault.CredentialSources, source)
}

func (vault *IdentityVault) DeleteIdentity(id []byte) bool {
	for i, source := range vault.CredentialSources {
		if bytes.Equal(source.ID, id) {
			vault.CredentialSources[i] = vault.CredentialSources[len(vault.CredentialSources)-1]
			vault.CredentialSources = vault.CredentialSources[:len(vault.CredentialSources)-1]
			return true
		}
	}
	return false
}

func (vault *IdentityVault) GetMatchingCredentialSources(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) []*CredentialSource {
	sources := make([]*CredentialSource, 0)
	for _, credentialSource := range vault.CredentialSources {
		if credentialSource.RelyingParty.ID == relyingPartyID {
			if allowList != nil {
				for _, allowedSource := range allowList {
					if bytes.Equal(allowedSource.ID, credentialSource.ID) {
						sources = append(sources, credentialSource)
						break
					}
				}
			} else {
				sources = append(sources, credentialSource)
			}
		}
	}
	return sources
}

func (vault *IdentityVault) Export() []SavedCredentialSource {
	sources := make([]SavedCredentialSource, 0)
	for _, source := range vault.CredentialSources {
		key := cose.MarshalCOSEPrivateKey(source.PrivateKey)
		savedSource := SavedCredentialSource{
			Type:             source.Type,
			ID:               source.ID,
			PrivateKey:       key,
			RelyingParty:     *source.RelyingParty,
			User:             *source.User,
			SignatureCounter: source.SignatureCounter,
		}
		if source.HMACSecret != nil {
			savedSource.CredRandomWithUV = source.HMACSecret.CredRandomWithUV
			savedSource.CredRandomWithoutUV = source.HMACSecret.CredRandomWithoutUV
		}
		sources = append(sources, savedSource)
	}
	return sources
}

func (vault *IdentityVault) Import(sources []SavedCredentialSource) error {
	for _, source := range sources {
		key, err := cose.UnmarshalCOSEPrivateKey(source.PrivateKey)
		if err != nil {
			oldFormatKey, err := x509.ParseECPrivateKey(source.PrivateKey)
			if err != nil {
				return fmt.Errorf("Invalid private key for source: %w", err)
			}
			key = &cose.SupportedCOSEPrivateKey{ECDSA: oldFormatKey}
		}
		decodedSource := CredentialSource{
			Type:             source.Type,
			ID:               source.ID,
			PrivateKey:       key,
			RelyingParty:     &source.RelyingParty,
			User:             &source.User,
			SignatureCounter: source.SignatureCounter,
		}
		// Keep whatever was stored, even if malformed: dropping it would be
		// persisted on the next save and permanently change PRF outputs.
		if len(source.CredRandomWithUV) > 0 || len(source.CredRandomWithoutUV) > 0 {
			decodedSource.HMACSecret = &HMACSecret{
				CredRandomWithUV:    source.CredRandomWithUV,
				CredRandomWithoutUV: source.CredRandomWithoutUV,
			}
		}
		vault.AddIdentity(&decodedSource)
	}
	return nil
}
