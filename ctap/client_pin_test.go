package ctap

import (
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/test"
)

func TestSetPINAndGetPINToken(t *testing.T) {
	client := newPINCapableClient()
	server := NewCTAPServer(client)
	session := platformKeyAgreement(t, server)

	test.AssertEqual(t, session.setPIN(t, server, "1234"), ctap1ErrSuccess, "setPIN failed")
	code, token := session.getPINToken(t, server, "1234")
	test.AssertEqual(t, code, ctap1ErrSuccess, "getPINToken failed")
	test.AssertArrEqual(t, token, client.pinToken, "decrypted PIN token does not match")

	code, _ = session.getPINToken(t, server, "4321")
	test.AssertEqual(t, code, ctap2ErrPINInvalid, "wrong PIN was accepted")
}

func TestClientPINRejectsInvalidKeyAgreement(t *testing.T) {
	client := newPINCapableClient()
	server := NewCTAPServer(client)
	session := platformKeyAgreement(t, server)
	test.AssertEqual(t, session.setPIN(t, server, "1234"), ctap1ErrSuccess, "setPIN failed")

	offCurve := session.publicKey
	offCurve.Y = append([]byte{}, offCurve.Y...)
	offCurve.Y[31] ^= 1
	code, _ := sendCTAP(t, server, ctapCommandClientPIN, clientPINArgs{
		PINUVAuthProtocol: 1,
		SubCommand:        clientPinSubcommandGetPINToken,
		KeyAgreement:      &offCurve,
		PINHashEncoding:   make([]byte, 16),
	})
	test.AssertEqual(t, code, ctap1ErrInvalidParameter, "off-curve key agreement key was accepted")
	test.AssertEqual(t, client.pinRetries, int32(8), "invalid key agreement consumed a PIN retry")

	code, _ = sendCTAP(t, server, ctapCommandClientPIN, clientPINArgs{
		PINUVAuthProtocol: 1,
		SubCommand:        clientPinSubcommandGetPINToken,
		PINHashEncoding:   make([]byte, 16),
	})
	test.AssertEqual(t, code, ctap2ErrMissingParam, "missing key agreement key was accepted")

	code, _ = sendCTAP(t, server, ctapCommandClientPIN, clientPINArgs{
		PINUVAuthProtocol: 1,
		SubCommand:        clientPinSubcommandGetPINToken,
		KeyAgreement:      &cose.COSEEC2Key{},
		PINHashEncoding:   make([]byte, 16),
	})
	test.AssertEqual(t, code, ctap1ErrInvalidParameter, "empty key agreement key was accepted")
}

func TestKeyAgreementWithoutPINSupport(t *testing.T) {
	client := newPINCapableClient()
	client.pinSupported = false
	server := NewCTAPServer(client)

	// Succeeds (checked inside the helper) even though PIN support is off.
	session := platformKeyAgreement(t, server)

	test.AssertEqual(t, session.setPIN(t, server, "1234"), ctap1ErrInvalidCommand, "setPIN allowed without PIN support")
	code, _ := sendCTAP(t, server, ctapCommandClientPIN, clientPINArgs{
		PINUVAuthProtocol: 1,
		SubCommand:        clientPINSubcommandGetRetries,
	})
	test.AssertEqual(t, code, ctap1ErrInvalidCommand, "getRetries allowed without PIN support")
}

func TestNoPINSet(t *testing.T) {
	client := newPINCapableClient()
	server := NewCTAPServer(client)
	session := platformKeyAgreement(t, server)

	code, _ := session.getPINToken(t, server, "1234")
	test.AssertEqual(t, code, ctap2ErrNoPINSet, "getPINToken without a PIN should report PIN_NOT_SET")
	test.AssertEqual(t, client.pinRetries, int32(8), "getPINToken without a PIN consumed a retry")

	code, _ = sendCTAP(t, server, ctapCommandClientPIN, clientPINArgs{
		PINUVAuthProtocol: 1,
		SubCommand:        clientPINSubcommandChangePIN,
		KeyAgreement:      &session.publicKey,
		PINUVAuthParam:    make([]byte, 16),
		NewPINEncoding:    make([]byte, 64),
		PINHashEncoding:   make([]byte, 16),
	})
	test.AssertEqual(t, code, ctap2ErrNoPINSet, "changePIN without a PIN should report PIN_NOT_SET")
}
