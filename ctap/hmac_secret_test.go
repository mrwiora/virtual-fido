package ctap

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/test"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
	"github.com/fxamacker/cbor/v2"
)

type parsedAuthData struct {
	flags        authDataFlags
	credentialID []byte
	extensions   map[string]cbor.RawMessage
}

// parseAuthData decodes authenticator data independently of makeAuthData.
func parseAuthData(t *testing.T, data []byte) parsedAuthData {
	t.Helper()
	if len(data) < 37 {
		t.Fatalf("authData too short: %d", len(data))
	}
	parsed := parsedAuthData{flags: authDataFlags(data[32])}
	reader := bytes.NewReader(data[37:])
	if parsed.flags&authDataFlagAttestedDataIncluded != 0 {
		header := make([]byte, 18)
		if _, err := reader.Read(header); err != nil {
			t.Fatal(err)
		}
		idLength := int(header[16])<<8 | int(header[17])
		parsed.credentialID = make([]byte, idLength)
		if _, err := reader.Read(parsed.credentialID); err != nil {
			t.Fatal(err)
		}
		var publicKey cbor.RawMessage
		if err := cbor.NewDecoder(reader).Decode(&publicKey); err != nil {
			t.Fatal(err)
		}
		// The decoder may read ahead; resync on the encoded key length.
		offset := 37 + 18 + idLength + len(publicKey)
		reader = bytes.NewReader(data[offset:])
	}
	if parsed.flags&authDataFlagExtensionDataIncluded != 0 {
		if err := cbor.NewDecoder(reader).Decode(&parsed.extensions); err != nil {
			t.Fatalf("could not decode extensions: %s", err)
		}
	} else if reader.Len() != 0 {
		t.Fatalf("%d trailing bytes without ED flag", reader.Len())
	}
	return parsed
}

func makeCredentialWithExtensions(t *testing.T, server *CTAPServer, extensions map[string]interface{}) makeCredentialResponse {
	t.Helper()
	code, body := sendCTAP(t, server, ctapCommandMakeCredential, makeCredentialArgs{
		ClientDataHash: make([]byte, 32),
		RP:             &webauthn.PublicKeyCredentialRPEntity{ID: "example.com", Name: "Example"},
		User:           &webauthn.PublicKeyCrendentialUserEntity{ID: []byte{1, 2, 3}, Name: "alice", DisplayName: "Alice"},
		PubKeyCredParams: []webauthn.PublicKeyCredentialParams{
			{Type: "public-key", Algorithm: cose.COSE_ALGORITHM_ID_ES256},
		},
		Extensions: extensions,
	})
	test.AssertEqual(t, code, ctap1ErrSuccess, "makeCredential failed")
	var response makeCredentialResponse
	if err := cbor.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestMakeCredentialHMACSecret(t *testing.T) {
	server := NewCTAPServer(&dummyCTAPClient{})
	response := makeCredentialWithExtensions(t, server, map[string]interface{}{"hmac-secret": true})
	authData := parseAuthData(t, response.AuthData)
	test.Assert(t, authData.flags&authDataFlagExtensionDataIncluded != 0, "ED flag not set")
	var enabled bool
	if err := cbor.Unmarshal(authData.extensions["hmac-secret"], &enabled); err != nil || !enabled {
		t.Fatalf("expected hmac-secret: true, got %v (%v)", authData.extensions, err)
	}
}

func TestMakeCredentialWithoutHMACSecret(t *testing.T) {
	server := NewCTAPServer(&dummyCTAPClient{})
	for _, extensions := range []map[string]interface{}{nil, {"hmac-secret": false}} {
		response := makeCredentialWithExtensions(t, server, extensions)
		authData := parseAuthData(t, response.AuthData)
		test.Assert(t, authData.flags&authDataFlagExtensionDataIncluded == 0, "ED flag set without extension output")
	}
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

type assertionOptions struct {
	pinToken     []byte
	userPresence *bool
}

// getAssertionHMACSecret runs getAssertion with the given hmac-secret input
// and returns the status code and the parsed authenticator data.
func getAssertionHMACSecret(t *testing.T, server *CTAPServer, input *hmacSecretInput, options assertionOptions) (ctapStatusCode, parsedAuthData) {
	t.Helper()
	clientDataHash := make([]byte, 32)
	args := getAssertionArgs{
		RPID:           "example.com",
		ClientDataHash: clientDataHash,
		Options:        getAssertionOptions{UserPresence: options.userPresence},
	}
	if input != nil {
		args.Extensions = map[string]cbor.RawMessage{"hmac-secret": util.MarshalCBOR(input)}
	}
	if options.pinToken != nil {
		args.PINUVAuthParam = hmacSHA256(options.pinToken, clientDataHash)[:16]
		args.PINUVAuthProtocol = 1
	}
	code, body := sendCTAP(t, server, ctapCommandGetAssertion, args)
	if code != ctap1ErrSuccess {
		return code, parsedAuthData{}
	}
	var response getAssertionResponse
	if err := cbor.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	return code, parseAuthData(t, response.AuthenticatorData)
}

func (session platformSession) hmacSecretInput(t *testing.T, salts []byte) *hmacSecretInput {
	saltEnc := session.encrypt(t, salts)
	return &hmacSecretInput{
		KeyAgreement: &session.publicKey,
		SaltEnc:      saltEnc,
		SaltAuth:     session.authenticate(saltEnc),
	}
}

// evaluatePRF performs a full platform-side hmac-secret evaluation and
// returns the decrypted outputs.
func evaluatePRF(t *testing.T, server *CTAPServer, salts []byte, options assertionOptions) []byte {
	t.Helper()
	session := platformKeyAgreement(t, server)
	code, authData := getAssertionHMACSecret(t, server, session.hmacSecretInput(t, salts), options)
	test.AssertEqual(t, code, ctap1ErrSuccess, "getAssertion failed")
	test.Assert(t, authData.flags&authDataFlagExtensionDataIncluded != 0, "ED flag not set")
	var encrypted []byte
	if err := cbor.Unmarshal(authData.extensions["hmac-secret"], &encrypted); err != nil {
		t.Fatalf("missing hmac-secret output: %v", err)
	}
	test.AssertEqual(t, len(encrypted), len(salts), "output length does not match salt length")
	return session.decrypt(t, encrypted)
}

func newHMACSecretSetup(t *testing.T) (*dummyCTAPClient, *CTAPServer, *identities.HMACSecret) {
	client := newPINCapableClient()
	server := NewCTAPServer(client)
	makeCredentialWithExtensions(t, server, map[string]interface{}{"hmac-secret": true})
	return client, server, client.vault.CredentialSources[0].HMACSecret
}

func TestGetAssertionHMACSecretWithoutPIN(t *testing.T) {
	_, server, secret := newHMACSecretSetup(t)
	salt1, salt2 := crypto.RandomBytes(32), crypto.RandomBytes(32)

	output := evaluatePRF(t, server, util.Concat(salt1, salt2), assertionOptions{})
	test.AssertArrEqual(t, output[:32], hmacSHA256(secret.CredRandomWithoutUV, salt1), "first output is wrong")
	test.AssertArrEqual(t, output[32:], hmacSHA256(secret.CredRandomWithoutUV, salt2), "second output is wrong")

	// A new key agreement must yield the same PRF value.
	again := evaluatePRF(t, server, salt1, assertionOptions{})
	test.AssertArrEqual(t, again, output[:32], "output is not deterministic")
}

func TestGetAssertionHMACSecretWithoutPINSupport(t *testing.T) {
	client, server, secret := newHMACSecretSetup(t)
	client.pinSupported = false
	salt := crypto.RandomBytes(32)
	output := evaluatePRF(t, server, salt, assertionOptions{})
	test.AssertArrEqual(t, output, hmacSHA256(secret.CredRandomWithoutUV, salt), "output is wrong")
}

func TestGetAssertionHMACSecretUserVerification(t *testing.T) {
	_, server, secret := newHMACSecretSetup(t)
	salt := crypto.RandomBytes(32)
	withoutUV := evaluatePRF(t, server, salt, assertionOptions{})

	session := platformKeyAgreement(t, server)
	test.AssertEqual(t, session.setPIN(t, server, "1234"), ctap1ErrSuccess, "setPIN failed")
	code, pinToken := session.getPINToken(t, server, "1234")
	test.AssertEqual(t, code, ctap1ErrSuccess, "getPINToken failed")

	withUV := evaluatePRF(t, server, salt, assertionOptions{pinToken: pinToken})
	test.AssertArrEqual(t, withUV, hmacSHA256(secret.CredRandomWithUV, salt), "UV output is wrong")
	test.Assert(t, !bytes.Equal(withUV, withoutUV), "UV and non-UV outputs must differ")
}

func TestGetAssertionHMACSecretRequiresUserPresence(t *testing.T) {
	_, server, _ := newHMACSecretSetup(t)
	session := platformKeyAgreement(t, server)
	noPresence := false
	code, _ := getAssertionHMACSecret(t, server, session.hmacSecretInput(t, crypto.RandomBytes(32)), assertionOptions{userPresence: &noPresence})
	test.AssertEqual(t, code, ctap2ErrUnsupportedOption, "hmac-secret with up=false must be rejected")
}

func TestGetAssertionHMACSecretLegacyCredential(t *testing.T) {
	client, server, _ := newHMACSecretSetup(t)
	client.vault.CredentialSources[0].HMACSecret = nil
	session := platformKeyAgreement(t, server)
	code, authData := getAssertionHMACSecret(t, server, session.hmacSecretInput(t, crypto.RandomBytes(32)), assertionOptions{})
	test.AssertEqual(t, code, ctap1ErrSuccess, "getAssertion failed for credential without hmac-secret")
	test.Assert(t, authData.flags&authDataFlagExtensionDataIncluded == 0, "hmac-secret output returned for legacy credential")
}

func TestGetAssertionHMACSecretInvalidInput(t *testing.T) {
	_, server, _ := newHMACSecretSetup(t)
	session := platformKeyAgreement(t, server)

	badAuth := session.hmacSecretInput(t, crypto.RandomBytes(32))
	badAuth.SaltAuth = make([]byte, 16)
	code, _ := getAssertionHMACSecret(t, server, badAuth, assertionOptions{})
	test.AssertEqual(t, code, ctap2ErrPINAuthInvalid, "wrong saltAuth accepted")

	badLength := session.hmacSecretInput(t, crypto.RandomBytes(48))
	code, _ = getAssertionHMACSecret(t, server, badLength, assertionOptions{})
	test.AssertEqual(t, code, ctap1ErrInvalidParameter, "48-byte salt accepted")

	badLengthAndAuth := session.hmacSecretInput(t, crypto.RandomBytes(48))
	badLengthAndAuth.SaltAuth = make([]byte, 16)
	code, _ = getAssertionHMACSecret(t, server, badLengthAndAuth, assertionOptions{})
	test.AssertEqual(t, code, ctap2ErrPINAuthInvalid, "saltAuth must be verified before the salt length")

	missing := session.hmacSecretInput(t, crypto.RandomBytes(32))
	missing.SaltAuth = nil
	code, _ = getAssertionHMACSecret(t, server, missing, assertionOptions{})
	test.AssertEqual(t, code, ctap2ErrMissingParam, "missing saltAuth accepted")

	offCurve := session.hmacSecretInput(t, crypto.RandomBytes(32))
	key := *offCurve.KeyAgreement
	key.Y = append([]byte{}, key.Y...)
	key.Y[31] ^= 1
	offCurve.KeyAgreement = &key
	code, _ = getAssertionHMACSecret(t, server, offCurve, assertionOptions{})
	test.AssertEqual(t, code, ctap1ErrInvalidParameter, "off-curve key accepted")

	protocol2 := session.hmacSecretInput(t, crypto.RandomBytes(32))
	protocol2.PINUVAuthProtocol = 2
	code, _ = getAssertionHMACSecret(t, server, protocol2, assertionOptions{})
	test.AssertEqual(t, code, ctap1ErrInvalidParameter, "unsupported PIN protocol accepted")
}
