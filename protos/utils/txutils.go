/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	crypto2 "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/hyperledger/fabric/common/flogging"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"bytes"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/peer"
)

var logger = flogging.MustGetLogger("txutils")

// GetPayloads get's the underlying payload objects in a TransactionAction
func GetPayloads(txActions *peer.TransactionAction) (*peer.ChaincodeActionPayload, *peer.ChaincodeAction, error) {
	// TODO: pass in the tx type (in what follows we're assuming the type is ENDORSER_TRANSACTION)
	ccPayload := &peer.ChaincodeActionPayload{}
	err := proto.Unmarshal(txActions.Payload, ccPayload)
	if err != nil {
		return nil, nil, err
	}

	if ccPayload.Action == nil || ccPayload.Action.ProposalResponsePayload == nil {
		return nil, nil, fmt.Errorf("no payload in ChaincodeActionPayload")
	}
	pRespPayload := &peer.ProposalResponsePayload{}
	err = proto.Unmarshal(ccPayload.Action.ProposalResponsePayload, pRespPayload)
	if err != nil {
		return nil, nil, err
	}

	if pRespPayload.Extension == nil {
		return nil, nil, fmt.Errorf("response payload is missing extension")
	}

	respPayload := &peer.ChaincodeAction{}
	err = proto.Unmarshal(pRespPayload.Extension, respPayload)
	if err != nil {
		return ccPayload, nil, err
	}
	return ccPayload, respPayload, nil
}

// GetEnvelopeFromBlock gets an envelope from a block's Data field.
func GetEnvelopeFromBlock(data []byte) (*common.Envelope, error) {
	//Block always begins with an envelope
	var err error
	env := &common.Envelope{}
	if err = proto.Unmarshal(data, env); err != nil {
		return nil, fmt.Errorf("Error getting envelope(%s)", err)
	}

	return env, nil
}

// CreateSignedEnvelope creates a signed envelope of the desired type, with marshaled dataMsg and signs it
func CreateSignedEnvelope(txType common.HeaderType, channelID string, signer crypto.LocalSigner, dataMsg proto.Message, msgVersion int32, epoch uint64) (*common.Envelope, error) {
	return CreateSignedEnvelopeWithTLSBinding(txType, channelID, signer, dataMsg, msgVersion, epoch, nil)
}

// CreateSignedEnvelopeWithTLSBinding creates a signed envelope of the desired type, with marshaled dataMsg and signs it.
// It also includes a TLS cert hash into the channel header
func CreateSignedEnvelopeWithTLSBinding(txType common.HeaderType, channelID string, signer crypto.LocalSigner, dataMsg proto.Message, msgVersion int32, epoch uint64, tlsCertHash []byte) (*common.Envelope, error) {
	payloadChannelHeader := MakeChannelHeader(txType, msgVersion, channelID, epoch)
	payloadChannelHeader.TlsCertHash = tlsCertHash
	var err error
	payloadSignatureHeader := &common.SignatureHeader{}

	if signer != nil {
		payloadSignatureHeader, err = signer.NewSignatureHeader()
		if err != nil {
			return nil, err
		}
	}

	data, err := proto.Marshal(dataMsg)
	if err != nil {
		return nil, err
	}

	paylBytes := MarshalOrPanic(&common.Payload{
		Header: MakePayloadHeader(payloadChannelHeader, payloadSignatureHeader),
		Data:   data,
	})

	var sig []byte
	if signer != nil {
		sig, err = signer.Sign(paylBytes)
		if err != nil {
			return nil, err
		}
	}

	return &common.Envelope{Payload: paylBytes, Signature: sig}, nil
}

// CreateSignedTx assembles an Envelope message from proposal, endorsements, and a signer.
// This function should be called by a client when it has collected enough endorsements
// for a proposal to create a transaction and submit it to peers for ordering
func CreateSignedTx(proposal *peer.Proposal, signer msp.SigningIdentity, resps ...*peer.ProposalResponse) (*common.Envelope, error) {
	if len(resps) == 0 {
		return nil, fmt.Errorf("At least one proposal response is necessary")
	}

	// the original header
	hdr, err := GetHeader(proposal.Header)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal the proposal header")
	}

	// the original payload
	pPayl, err := GetChaincodeProposalPayload(proposal.Payload)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal the proposal payload")
	}

	// check that the signer is the same that is referenced in the header
	// TODO: maybe worth removing?
	signerBytes, err := signer.Serialize()
	if err != nil {
		return nil, err
	}

	shdr, err := GetSignatureHeader(hdr.SignatureHeader)
	if err != nil {
		return nil, err
	}

	if bytes.Compare(signerBytes, shdr.Creator) != 0 {
		return nil, fmt.Errorf("The signer needs to be the same as the one referenced in the header")
	}

	// get header extensions so we have the visibility field
	hdrExt, err := GetChaincodeHeaderExtension(hdr)
	if err != nil {
		return nil, err
	}

	// ensure that all actions are bitwise equal and that they are successful
	var a1 []byte
	for n, r := range resps {
		if n == 0 {
			a1 = r.Payload
			if r.Response.Status != 200 {
				return nil, fmt.Errorf("Proposal response was not successful, error code %d, msg %s", r.Response.Status, r.Response.Message)
			}
			continue
		}

		if bytes.Compare(a1, r.Payload) != 0 {
			return nil, fmt.Errorf("ProposalResponsePayloads do not match")
		}
	}

	// fill endorsements
	endorsements := make([]*peer.Endorsement, len(resps))
	for n, r := range resps {
		endorsements[n] = r.Endorsement
	}

	// create ChaincodeEndorsedAction
	cea := &peer.ChaincodeEndorsedAction{ProposalResponsePayload: resps[0].Payload, Endorsements: endorsements}

	// obtain the bytes of the proposal payload that will go to the transaction
	propPayloadBytes, err := GetBytesProposalPayloadForTx(pPayl, hdrExt.PayloadVisibility)
	if err != nil {
		return nil, err
	}

	// serialize the chaincode action payload
	cap := &peer.ChaincodeActionPayload{ChaincodeProposalPayload: propPayloadBytes, Action: cea}
	capBytes, err := GetBytesChaincodeActionPayload(cap)
	if err != nil {
		return nil, err
	}

	// create a transaction
	taa := &peer.TransactionAction{Header: hdr.SignatureHeader, Payload: capBytes}
	taas := make([]*peer.TransactionAction, 1)
	taas[0] = taa
	tx := &peer.Transaction{Actions: taas}

	// serialize the tx
	txBytes, err := GetBytesTransaction(tx)
	if err != nil {
		return nil, err
	}

	// create the payload
	payl := &common.Payload{Header: hdr, Data: txBytes}
	paylBytes, err := GetBytesPayload(payl)
	if err != nil {
		return nil, err
	}

	// // FGODINHO
	// // here we reconstruct a signature from endorsements and our own signature
	// // TODO switch between multisig and thresh (multisig is commented)

	// fmt.Println("Reconstructing threshold signature from endorsing sig shares")
	// var sig []byte

	// // first put the nr of endorsements
	// nrEndorsements := make([]byte, 4)
	// binary.LittleEndian.PutUint32(nrEndorsements, uint32(len(resps)))
	// sig = nrEndorsements

	// iveSigned := false
	// for _, en := range endorsements {
	// 	// check if signed by this peer
	// 	if bytes.Equal(en.Endorser, signerBytes) {
	// 		iveSigned = true
	// 	}
	// 	// then put the size of the upcoming sig
	// 	sigLen := make([]byte, 4)
	// 	binary.LittleEndian.PutUint32(sigLen, uint32(len(en.Signature)))
	// 	sig = append(sig, sigLen...)
	// 	// then put the actual sig
	// 	sig = append(sig, en.Signature...)

	// }

	// // this peer has not signed yet, append its signature
	// if !iveSigned {
	// 	fmt.Println("Adding submitting peer own sig share to signature")
	// 	mySigShare, err := signThresh(append(paylBytes, signerBytes...))
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	// then put the size of the upcoming sig
	// 	mySigLen := make([]byte, 4)
	// 	binary.LittleEndian.PutUint32(mySigLen, uint32(len(mySigShare)))
	// 	sig = append(sig, mySigLen...)
	// 	// then put the actual sig
	// 	sig = append(sig, mySigShare...)
	// }

	// sign the payload
	sig, err := signer.Sign(paylBytes)
	if err != nil {
		return nil, err
	}

	// here's the envelope
	return &common.Envelope{Payload: paylBytes, Signature: sig}, nil
}

// MIGUEL BEGIN
/**
// A Signer is can create signatures that verify against a public key.
// loadPrivateKey loads an parses a PEM encoded private key file.
func loadPublicKey(path string) (Unsigner, error) {

	pkiPublicKey, isSet := os.LookupEnv("PKI_PUBLIC_KEY")
	if !isSet {
		return nil, fmt.Errorf("Could not obtain pki public key from environment variable: PKI_PUBLIC_KEY")
	}

	pkiPublicKeyPem := strings.Replace(pkiPublicKey, `\n`, "\n", -1) //with break lines
	return parsePublicKey([]byte(pkiPublicKeyPem))

}

// parsePublicKey parses a PEM encoded private key.
func parsePublicKey(pemBytes []byte) (Unsigner, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}

	return newUnsignerFromKey(rawkey)
}

// loadPrivateKey loads an parses a PEM encoded private key file.
func loadPrivateKey(path string) (Signer, error) {
	pkiPrivateKey, isSet := os.LookupEnv("PKI_PRIVATE_KEY")
	if !isSet {
		return nil, fmt.Errorf("Could not obtain pki private key from environment variable: PKI_PRIVATE_KEY")
	}

	pkiPrivateKeyPem := strings.Replace(pkiPrivateKey, `\n`, "\n", -1) //with break lines
	return parsePrivateKey([]byte(pkiPrivateKeyPem))
}

// parsePublicKey parses a PEM encoded private key.
func parsePrivateKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

// A Signer is can create signatures that verify against a public key.
type Signer interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Sign(data []byte) ([]byte, error)
}

// A Signer is can create signatures that verify against a public key.
type Unsigner interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Unsign(data[]byte, sig []byte) error
}

func newSignerFromKey(k interface{}) (Signer, error) {
	var sshKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sshKey = &rsaPrivateKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

func newUnsignerFromKey(k interface{}) (Unsigner, error) {
	var sshKey Unsigner
	switch t := k.(type) {
	case *rsa.PublicKey:
		sshKey = &rsaPublicKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

type rsaPublicKey struct {
	*rsa.PublicKey
}

type rsaPrivateKey struct {
	*rsa.PrivateKey
}

// Sign signs data with rsa-sha256
func (r *rsaPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto2.SHA256, d)
}

// Unsign verifies the message using a rsa-sha256 signature
func (r *rsaPublicKey) Unsign(message []byte, sig []byte) error {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto2.SHA256, d, sig)
}

// /MIGUEL END
*/
// CreateProposalResponse creates a proposal response.
// MIGUEL - Changed args to include if transaction is to sign certificate and hash of the certificate
func CreateProposalResponse(hdrbytes []byte, payl []byte, response *peer.Response, results []byte, events []byte, ccid *peer.ChaincodeID, visibility []byte, signingEndorser msp.SigningIdentity, signingMethod []byte, pkiCurrSigMethod []byte, transactionToSignCertificate bool, certToSign []byte) (*peer.ProposalResponse, error) {
	hdr, err := GetHeader(hdrbytes)
	if err != nil {
		return nil, err
	}

	// obtain the proposal hash given proposal header, payload and the requested visibility
	pHashBytes, err := GetProposalHash1(hdr, payl, visibility)
	if err != nil {
		return nil, fmt.Errorf("Could not compute proposal hash: err %s", err)
	}

	// get the bytes of the proposal response payload - we need to sign them
	prpBytes, err := GetBytesProposalResponsePayload(pHashBytes, response, results, events, ccid)
	if err != nil {
		return nil, errors.New("Failure while marshaling the ProposalResponsePayload")
	}

	// serialize the signing identity
	endorser, err := signingEndorser.Serialize()
	if err != nil {
		return nil, fmt.Errorf("Could not serialize the signing identity for %s, err %s", signingEndorser.GetIdentifier(), err)
	}

	// sign the concatenation of the proposal response and the serialized endorser identity with this endorser's key

	// FGODINHO
	// this is the endorsement phase. here, each peer endorses the tx with his sig share

	sigMethod := string(signingMethod)
	// switch between multisig and threshsig


	var signature []byte
	var clientCertEndorserSignature []byte // if transaction is regarding signing a client self-signed certificate
	var clientCertEndorserSignatureString string
	if sigMethod == "multisig" {
		signature, err = signingEndorser.Sign(append(prpBytes, endorser...))
	} else if sigMethod == "threshsig" {
		signature, err = signThresh(prpBytes)
	}

	//MIGUEL BEGIN
	//Sign certificate if it is a transaction regarding a certificate's signature
	if(transactionToSignCertificate){
		pkiSigMethod := string(pkiCurrSigMethod)

		if pkiSigMethod == "multisig" {
			logger.Debugf("Transaction related to signing certificate")
			logger.Debugf("ESCC Signing client certificate")

			// Obtain private key from environment (public and private key set in docker compose peer config file)
			pkiPrivateKey, isSet := os.LookupEnv("PKI_PRIVATE_KEY")
			if !isSet {
				return nil, fmt.Errorf("Could not obtain pki private key from environment variable: PKI_PRIVATE_KEY")
			}

			pkiPrivateKeyPem := strings.Replace(pkiPrivateKey, `\n`, "\n", -1) //with break lines

			block, _ := pem.Decode([]byte(pkiPrivateKeyPem))
			key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

			h := sha256.New()
			h.Write(certToSign)
			d := h.Sum(nil)

			clientCertEndorserSignature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto2.SHA256, d)
			if err != nil {
				panic(err)
			}

			clientCertEndorserSignatureString = base64.StdEncoding.EncodeToString(clientCertEndorserSignature)

			fmt.Printf("Signed client certificate using multisig: %v\n\n", clientCertEndorserSignatureString)
		} else if pkiSigMethod == "threshsig" {
			logger.Debugf("ESCC Signing client certificate")
			clientCertEndorserSignature, err := signTreshPKI(certToSign)
			if err != nil {
				return nil, fmt.Errorf("Could not sign a client certificate (PKI Blockchain Component), err %s", err)
			}
			clientCertEndorserSignatureString = clientCertEndorserSignature
			logger.Debugf("Signed client certificate using threshsig: %v\n", clientCertEndorserSignature)
			logger.Debugf("Signed client certificate using threshsig in String: %v\n", clientCertEndorserSignatureString)
		}else {
			logger.Debugf("PKI Signature method not recognized: %v\n", pkiSigMethod)
		}
	}


	//MIGUEL END

	if err != nil {
		return nil, fmt.Errorf("Could not sign the proposal response payload, err %s", err)
	}

	// MIGUEL - Changed Proposal Response to include if contains endorser signature regarding clients certificate and the signature of the certificate
	resp := &peer.ProposalResponse{
		// Timestamp: TODO!
		Version:     1, // TODO: pick right version number
		Endorsement: &peer.Endorsement{Signature: signature, Endorser: endorser, EndorsementMethod: signingMethod},
		Payload:     prpBytes,
		Response:    &peer.Response{Status: 200, Message: "OK"},
		ContainsClientCertSignatureByEndorser: transactionToSignCertificate,
		ClientCertSignatureByEndorser: clientCertEndorserSignature,
		ClientCertEndorserSignatureString: clientCertEndorserSignatureString} //clientCertSignature is not used if transaction is not regarding signing a cert

	return resp, nil
}

type xspSignMsg struct {
	Id        int    `json:"id"`
	Signature string `json:"signature"`
}

func signThresh(msg []byte) (signature []byte, err error) {

	// first hash the msg
	hasher := sha1.New()
	hasher.Write(msg)
	digest := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	shareEnvVar, isSet := os.LookupEnv("THRESH_SIG_KEY_SHARE")
	if !isSet {
		return nil, fmt.Errorf("Could not obtain key share from environment variable: THRESH_SIG_KEY_SHARE")
	}

	shareBytes := []byte(shareEnvVar)

	// open unix domain socket connection
	intervalEnvVar, isSet := os.LookupEnv("XSP_DIGEST_INTERVAL_MILLIS")
	var interval time.Duration
	if !isSet {
		interval = 200
	} else {
		interval, _ = time.ParseDuration(intervalEnvVar)
	}
	time.Sleep(interval * time.Millisecond) // sleep 200 millis to avoid overwriting anything the socket may have
	conn, err := net.Dial("unix", "/tmp/hlf-xsp.sock")
	if err != nil {
		return nil, fmt.Errorf("Could not start connection pool to java component: %s", err)
	}

	// defer connection for closing after sing concludes
	defer conn.Close()

	// send away the call
	var bufferWr bytes.Buffer
	bufferWr.WriteString("__CALL_THRESHSIG_SIGN\n")
	bufferWr.WriteString("{\"share\":\"")
	bufferWr.WriteString(string(shareBytes))
	bufferWr.WriteString("\",\"msg\":\"")
	bufferWr.WriteString(string(digest))
	bufferWr.WriteString("\"}")
	payload := bufferWr.String()
	_, err = conn.Write([]byte(payload))

	if err != nil {
		return nil, fmt.Errorf("Unable to send payload to java component for signing: %s", err)
	}

	// read response from socket
	signThreshMtuEnvVar, isSet := os.LookupEnv("PEER_SIGN_THRESHOLD_MTU")
	var signThreshMtu int
	if !isSet {
		signThreshMtu = 4096
	} else {
		signThreshMtu, _ = strconv.Atoi(signThreshMtuEnvVar)
	}
	bufferRd := make([]byte, signThreshMtu)
	nr, err := conn.Read(bufferRd)
	if err != nil {
		return nil, fmt.Errorf("Unable to read payload from java component: %s", err)
	}

	// break the response into its parts
	response := strings.Split(string(bufferRd[:nr]), "\n")

	// check the call
	if response[0] != "__RETU_THRESHSIG_SIGN" {
		return nil, fmt.Errorf("Wrong response from java component: %s", response[0])
	}

	// parse sig
	var sigma xspSignMsg
	err = json.Unmarshal([]byte(response[1]), &sigma)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse payload from java component: %s", err)
	}

	return []byte(sigma.Signature), nil
}

//MIGUEL - BEGIN
//Used to sign certificates with threshold share key
func signTreshPKI(msg []byte) (signature string, err error) {

	// first hash the msg
	hasher := sha1.New()
	hasher.Write(msg)
	digest := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	shareEnvVar, isSet := os.LookupEnv("PKI_THRESH_KEY_SHARE")
	if !isSet {
		return "", fmt.Errorf("Could not obtain key share from environment variable: PKI_THRESH_KEY_SHARE")
	}

	shareBytes := []byte(shareEnvVar)

	// open unix domain socket connection
	intervalEnvVar, isSet := os.LookupEnv("XSP_DIGEST_INTERVAL_MILLIS")
	var interval time.Duration
	if !isSet {
		interval = 200
	} else {
		interval, _ = time.ParseDuration(intervalEnvVar)
	}
	time.Sleep(interval * time.Millisecond) // sleep 200 millis to avoid overwriting anything the socket may have
	conn, err := net.Dial("unix", "/tmp/hlf-xsp.sock")
	if err != nil {
		return "", fmt.Errorf("Could not start connection pool to java component: %s", err)
	}

	// defer connection for closing after sing concludes
	defer conn.Close()

	// send away the call
	var bufferWr bytes.Buffer
	bufferWr.WriteString("__CALL_THRESHSIG_SIGN\n")
	bufferWr.WriteString("{\"share\":\"")
	bufferWr.WriteString(string(shareBytes))
	bufferWr.WriteString("\",\"msg\":\"")
	bufferWr.WriteString(string(digest))
	bufferWr.WriteString("\"}")
	payload := bufferWr.String()
	_, err = conn.Write([]byte(payload))

	if err != nil {
		return "", fmt.Errorf("Unable to send payload to java component for signing: %s", err)
	}

	// read response from socket
	signThreshMtuEnvVar, isSet := os.LookupEnv("PEER_SIGN_THRESHOLD_MTU")
	var signThreshMtu int
	if !isSet {
		signThreshMtu = 4096
	} else {
		signThreshMtu, _ = strconv.Atoi(signThreshMtuEnvVar)
	}
	bufferRd := make([]byte, signThreshMtu)
	nr, err := conn.Read(bufferRd)
	if err != nil {
		return "", fmt.Errorf("Unable to read payload from java component: %s", err)
	}

	// break the response into its parts
	response := strings.Split(string(bufferRd[:nr]), "\n")

	// check the call
	if response[0] != "__RETU_THRESHSIG_SIGN" {
		return "", fmt.Errorf("Wrong response from java component: %s", response[0])
	}

	// parse sig
	var sigma xspSignMsg
	err = json.Unmarshal([]byte(response[1]), &sigma)
	if err != nil {
		return "", fmt.Errorf("Unable to parse payload from java component: %s", err)
	}

	return sigma.Signature, nil
}

//MIGUEL - END

// CreateProposalResponseFailure creates a proposal response for cases where
// endorsement proposal fails either due to a endorsement failure or a chaincode
// failure (chaincode response status >= shim.ERRORTHRESHOLD)
func CreateProposalResponseFailure(hdrbytes []byte, payl []byte, response *peer.Response, results []byte, events []byte, ccid *peer.ChaincodeID, visibility []byte) (*peer.ProposalResponse, error) {
	hdr, err := GetHeader(hdrbytes)
	if err != nil {
		return nil, err
	}

	// obtain the proposal hash given proposal header, payload and the requested visibility
	pHashBytes, err := GetProposalHash1(hdr, payl, visibility)
	if err != nil {
		return nil, fmt.Errorf("Could not compute proposal hash: err %s", err)
	}

	// get the bytes of the proposal response payload
	prpBytes, err := GetBytesProposalResponsePayload(pHashBytes, response, results, events, ccid)
	if err != nil {
		return nil, errors.New("Failure while marshaling the ProposalResponsePayload")
	}

	resp := &peer.ProposalResponse{
		// Timestamp: TODO!
		Payload:  prpBytes,
		Response: &peer.Response{Status: 500, Message: "Chaincode Error"}}

	return resp, nil
}

// GetSignedProposal returns a signed proposal given a Proposal message and a signing identity
func GetSignedProposal(prop *peer.Proposal, signer msp.SigningIdentity) (*peer.SignedProposal, error) {
	// check for nil argument
	if prop == nil || signer == nil {
		return nil, fmt.Errorf("Nil arguments")
	}

	propBytes, err := GetBytesProposal(prop)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(propBytes)
	if err != nil {
		return nil, err
	}

	return &peer.SignedProposal{ProposalBytes: propBytes, Signature: signature}, nil
}

// GetSignedEvent returns a signed event given an Event message and a signing identity
func GetSignedEvent(evt *peer.Event, signer msp.SigningIdentity) (*peer.SignedEvent, error) {
	// check for nil argument
	if evt == nil || signer == nil {
		return nil, errors.New("nil arguments")
	}

	evtBytes, err := proto.Marshal(evt)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(evtBytes)
	if err != nil {
		return nil, err
	}

	return &peer.SignedEvent{EventBytes: evtBytes, Signature: signature}, nil
}

// MockSignedEndorserProposalOrPanic creates a SignedProposal with the passed arguments
func MockSignedEndorserProposalOrPanic(chainID string, cs *peer.ChaincodeSpec, creator, signature []byte) (*peer.SignedProposal, *peer.Proposal) {
	prop, _, err := CreateChaincodeProposal(
		common.HeaderType_ENDORSER_TRANSACTION,
		chainID,
		&peer.ChaincodeInvocationSpec{ChaincodeSpec: cs},
		creator)
	if err != nil {
		panic(err)
	}

	propBytes, err := GetBytesProposal(prop)
	if err != nil {
		panic(err)
	}

	return &peer.SignedProposal{ProposalBytes: propBytes, Signature: signature}, prop
}

func MockSignedEndorserProposal2OrPanic(chainID string, cs *peer.ChaincodeSpec, signer msp.SigningIdentity) (*peer.SignedProposal, *peer.Proposal) {
	serializedSigner, err := signer.Serialize()
	if err != nil {
		panic(err)
	}

	prop, _, err := CreateChaincodeProposal(
		common.HeaderType_ENDORSER_TRANSACTION,
		chainID,
		&peer.ChaincodeInvocationSpec{ChaincodeSpec: &peer.ChaincodeSpec{}},
		serializedSigner)
	if err != nil {
		panic(err)
	}

	sProp, err := GetSignedProposal(prop, signer)
	if err != nil {
		panic(err)
	}

	return sProp, prop
}

// GetBytesProposalPayloadForTx takes a ChaincodeProposalPayload and returns its serialized
// version according to the visibility field
func GetBytesProposalPayloadForTx(payload *peer.ChaincodeProposalPayload, visibility []byte) ([]byte, error) {
	// check for nil argument
	if payload == nil /* || visibility == nil */ {
		return nil, fmt.Errorf("Nil arguments")
	}

	// strip the transient bytes off the payload - this needs to be done no matter the visibility mode
	cppNoTransient := &peer.ChaincodeProposalPayload{Input: payload.Input, TransientMap: nil}
	cppBytes, err := GetBytesChaincodeProposalPayload(cppNoTransient)
	if err != nil {
		return nil, errors.New("Failure while marshalling the ChaincodeProposalPayload!")
	}

	// currently the fabric only supports full visibility: this means that
	// there are no restrictions on which parts of the proposal payload will
	// be visible in the final transaction; this default approach requires
	// no additional instructions in the PayloadVisibility field; however
	// the fabric may be extended to encode more elaborate visibility
	// mechanisms that shall be encoded in this field (and handled
	// appropriately by the peer)

	return cppBytes, nil
}

// GetProposalHash2 gets the proposal hash - this version
// is called by the committer where the visibility policy
// has already been enforced and so we already get what
// we have to get in ccPropPayl
func GetProposalHash2(header *common.Header, ccPropPayl []byte) ([]byte, error) {
	// check for nil argument
	if header == nil ||
		header.ChannelHeader == nil ||
		header.SignatureHeader == nil ||
		ccPropPayl == nil {
		return nil, fmt.Errorf("Nil arguments")
	}

	hash, err := factory.GetDefault().GetHash(&bccsp.SHA256Opts{})
	if err != nil {
		return nil, fmt.Errorf("Failed instantiating hash function [%s]", err)
	}
	hash.Write(header.ChannelHeader)   // hash the serialized Channel Header object
	hash.Write(header.SignatureHeader) // hash the serialized Signature Header object
	hash.Write(ccPropPayl)             // hash the bytes of the chaincode proposal payload that we are given

	return hash.Sum(nil), nil
}

// GetProposalHash1 gets the proposal hash bytes after sanitizing the
// chaincode proposal payload according to the rules of visibility
func GetProposalHash1(header *common.Header, ccPropPayl []byte, visibility []byte) ([]byte, error) {
	// check for nil argument
	if header == nil ||
		header.ChannelHeader == nil ||
		header.SignatureHeader == nil ||
		ccPropPayl == nil /* || visibility == nil */ {
		return nil, fmt.Errorf("Nil arguments")
	}

	// unmarshal the chaincode proposal payload
	cpp := &peer.ChaincodeProposalPayload{}
	err := proto.Unmarshal(ccPropPayl, cpp)
	if err != nil {
		return nil, errors.New("Failure while unmarshalling the ChaincodeProposalPayload!")
	}

	ppBytes, err := GetBytesProposalPayloadForTx(cpp, visibility)
	if err != nil {
		return nil, err
	}

	hash2, err := factory.GetDefault().GetHash(&bccsp.SHA256Opts{})
	if err != nil {
		return nil, fmt.Errorf("Failed instantiating hash function [%s]", err)
	}
	hash2.Write(header.ChannelHeader)   // hash the serialized Channel Header object
	hash2.Write(header.SignatureHeader) // hash the serialized Signature Header object
	hash2.Write(ppBytes)                // hash of the part of the chaincode proposal payload that will go to the tx

	return hash2.Sum(nil), nil
}
