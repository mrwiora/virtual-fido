package ctap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/fxamacker/cbor/v2"
)

// This file implements the platform (browser) side of CTAP2 PIN protocol 1
// using only the standard library, so tests do not rely on the
// authenticator's own crypto helpers.

func newPINCapableClient() *dummyCTAPClient {
	return &dummyCTAPClient{
		pinSupported: true,
		pinRetries:   8,
		keyAgreement: crypto.GenerateECDHKey(),
		pinToken:     crypto.RandomBytes(16),
	}
}

func sendCTAP(t *testing.T, server *CTAPServer, command ctapCommand, args interface{}) (ctapStatusCode, []byte) {
	t.Helper()
	message := []byte{byte(command)}
	if args != nil {
		message = util.Concat(message, util.MarshalCBOR(args))
	}
	response := server.HandleMessage(message)
	if len(response) == 0 {
		t.Fatalf("empty response")
	}
	return ctapStatusCode(response[0]), response[1:]
}

type platformSession struct {
	publicKey    cose.COSEEC2Key
	sharedSecret []byte
}

// platformKeyAgreement performs getKeyAgreement and derives the protocol 1
// shared secret the way a platform would.
func platformKeyAgreement(t *testing.T, server *CTAPServer) platformSession {
	t.Helper()
	code, body := sendCTAP(t, server, ctapCommandClientPIN, clientPINArgs{
		PINUVAuthProtocol: 1,
		SubCommand:        clientPinSubcommandGetKeyAgreement,
	})
	if code != ctap1ErrSuccess {
		t.Fatalf("getKeyAgreement failed: 0x%02x", code)
	}
	var response clientPINResponse
	if err := cbor.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	authKey := response.KeyAgreement
	if authKey.Curve != int8(cose.COSE_CURVE_ID_P256) {
		t.Fatalf("unexpected curve %d", authKey.Curve)
	}
	remote, err := ecdh.P256().NewPublicKey(util.Concat([]byte{0x04}, authKey.X, authKey.Y))
	if err != nil {
		t.Fatalf("authenticator key agreement key is invalid: %s", err)
	}
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	z, err := private.ECDH(remote)
	if err != nil {
		t.Fatal(err)
	}
	sharedSecret := sha256.Sum256(z)
	public := private.PublicKey().Bytes()
	return platformSession{
		publicKey: cose.COSEEC2Key{
			KeyType:   int8(cose.COSE_KEY_TYPE_EC2),
			Algorithm: int8(cose.COSE_ALGORITHM_ID_ECDH_HKDF_256),
			Curve:     int8(cose.COSE_CURVE_ID_P256),
			X:         public[1:33],
			Y:         public[33:65],
		},
		sharedSecret: sharedSecret[:],
	}
}

func (session platformSession) authenticate(data []byte) []byte {
	mac := hmac.New(sha256.New, session.sharedSecret)
	mac.Write(data)
	return mac.Sum(nil)[:16]
}

func (session platformSession) encrypt(t *testing.T, data []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(session.sharedSecret)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(out, data)
	return out
}

func (session platformSession) decrypt(t *testing.T, data []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(session.sharedSecret)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(out, data)
	return out
}

// setPIN sets a PIN through the CTAP setPIN subcommand.
func (session platformSession) setPIN(t *testing.T, server *CTAPServer, pin string) ctapStatusCode {
	t.Helper()
	padded := make([]byte, 64)
	copy(padded, pin)
	newPINEnc := session.encrypt(t, padded)
	code, _ := sendCTAP(t, server, ctapCommandClientPIN, clientPINArgs{
		PINUVAuthProtocol: 1,
		SubCommand:        clientPINSubcommandSetPIN,
		KeyAgreement:      &session.publicKey,
		PINUVAuthParam:    session.authenticate(newPINEnc),
		NewPINEncoding:    newPINEnc,
	})
	return code
}

// getPINToken requests and decrypts a PIN token.
func (session platformSession) getPINToken(t *testing.T, server *CTAPServer, pin string) (ctapStatusCode, []byte) {
	t.Helper()
	pinHash := sha256.Sum256([]byte(pin))
	code, body := sendCTAP(t, server, ctapCommandClientPIN, clientPINArgs{
		PINUVAuthProtocol: 1,
		SubCommand:        clientPinSubcommandGetPINToken,
		KeyAgreement:      &session.publicKey,
		PINHashEncoding:   session.encrypt(t, pinHash[:16]),
	})
	if code != ctap1ErrSuccess {
		return code, nil
	}
	var response clientPINResponse
	if err := cbor.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	return code, session.decrypt(t, response.PinToken)
}
