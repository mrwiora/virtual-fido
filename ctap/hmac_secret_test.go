package ctap

import (
	"bytes"
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/test"
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
