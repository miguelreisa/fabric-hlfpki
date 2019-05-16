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

package escc

import (
	//"crypto"
	//"crypto/rand"
	//"crypto/rsa"
	"crypto/sha256"
	//"crypto/x509"
	//"encoding/base64"
	//"encoding/pem"
	"fmt"
	"strings"

	//"github.com/miguelreisa-fabric1.1/fabric-hlfpki/build/docker/gotools/obj/gopath/src/golang.org/x/tools/go/ssa/interp/testdata/src/strings"
	//"strings"

	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/protos/utils"
	putils "github.com/hyperledger/fabric/protos/utils"

	mspmgmt "github.com/hyperledger/fabric/msp/mgmt"
)

var logger = flogging.MustGetLogger("escc")
var cCSigMethods map[string][]byte // FGODINHO

// EndorserOneValidSignature implements the default endorsement policy, which is to
// sign the proposal hash and the read-write set
type EndorserOneValidSignature struct {
}

// Init is called once when the chaincode started the first time
func (e *EndorserOneValidSignature) Init(stub shim.ChaincodeStubInterface) pb.Response {
	cCSigMethods = make(map[string][]byte) // FGODINHO
	logger.Infof("Successfully initialized ESCC")
	return shim.Success(nil)
}

// Invoke is called to endorse the specified Proposal
// For now, we sign the input and return the endorsed result. Later we can expand
// the chaincode to provide more sophisticate policy processing such as enabling
// policy specification to be coded as a transaction of the chaincode and Client
// could select which policy to use for endorsement using parameter
// @return a marshalled proposal response
// Note that Peer calls this function with 4 mandatory arguments (and 2 optional ones):
// args[0] - function name (not used now)
// args[1] - serialized Header object
// args[2] - serialized ChaincodeProposalPayload object
// args[3] - ChaincodeID of executing chaincode
// args[4] - result of executing chaincode
// args[5] - binary blob of simulation results
// args[6] - serialized events
// args[7] - payloadVisibility
//
// NOTE: this chaincode is meant to sign another chaincode's simulation
// results. It should not manipulate state as any state change will be
// silently discarded: the only state changes that will be persisted if
// this endorsement is successful is what we are about to sign, which by
// definition can't be a state change of our own.
func (e *EndorserOneValidSignature) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	args := stub.GetArgs()
	if len(args) < 6 {
		return shim.Error(fmt.Sprintf("Incorrect number of arguments (expected a minimum of 5, provided %d)", len(args)))
	} else if len(args) > 8 {
		return shim.Error(fmt.Sprintf("Incorrect number of arguments (expected a maximum of 7, provided %d)", len(args)))
	}

	logger.Debugf("ESCC starts: %d args", len(args))

	// handle the header
	var hdr []byte
	if args[1] == nil {
		return shim.Error("serialized Header object is null")
	}

	hdr = args[1]

	// handle the proposal payload
	var payl []byte
	if args[2] == nil {
		return shim.Error("serialized ChaincodeProposalPayload object is null")
	}

	payl = args[2]

	// handle ChaincodeID
	if args[3] == nil {
		return shim.Error("ChaincodeID is null")
	}

	ccid, err := putils.UnmarshalChaincodeID(args[3])
	if err != nil {
		return shim.Error(err.Error())
	}

	// handle executing chaincode result
	// Status code < shim.ERRORTHRESHOLD can be endorsed
	if args[4] == nil {
		return shim.Error("Response of chaincode executing is null")
	}

	response, err := putils.GetResponse(args[4])
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get Response of executing chaincode: %s", err.Error()))
	}

	if response.Status >= shim.ERRORTHRESHOLD {
		return shim.Error(fmt.Sprintf("Status code less than %d will be endorsed, received status code: %d", shim.ERRORTHRESHOLD, response.Status))
	}

	responsePayload := string(response.Payload[:])
	logger.Debugf("Response Payload", responsePayload)
	logger.Debugf("Response String", response.String())
	logger.Debugf("Response GetMessage", response.GetMessage())
	logger.Debugf("Response Message", response.Message)


	// MIGUEL - BEGIN

	transactionToSignCertificate := false
	var clientCertHashToSign []byte


	if(strings.Contains(responsePayload,"SignCertificate")){
		transactionToSignCertificate = true
		s1 := strings.Split(responsePayload,":")[1]
		pkiClientCert := strings.Split(s1, "#########")[0]
		logger.Debugf("Client Cert PEM: ", pkiClientCert)

		/**
				//FOR DEV PURPOSES
				//Generate static key to test if signature is the same when the endorser signs
				pemString := `-----BEGIN RSA PRIVATE KEY-----
		MIIEpQIBAAKCAQEA0+ZhNo8/p035I8jw9yLWssJMXPMoifNG3mXL5UBByomczWy3
		GMTy8TnIMRM7WwQDamaS0XFXZlKlKWb/yssVseVkqaPZ8EXAWQnGp+yDpozlQVy9
		CPqQMQI1MwFIgSjt6gPvFv7Jg1Eth0iDswAd5Wzt7+edb4Bfd4wP1EHe5WvkauKv
		BZAHzWSbXDQdNP4iZYxmPCDMW8Z1NfXmO1S6zcf4w8kJ72i+IA/NUPug5KhyEM/2
		0k1D8kvcWmfe5IozTrkU7f+pzK1aTRCk8aY/hGPxB1AhFUDtcyLuprVYdFxsrS0i
		TtW7vB8xO/6vyQgd8teoPyHVflxvLGBEv/MGtwIDAQABAoIBAQCcPfuiIh+6Ofkh
		FLHwV+Tc6/0ocDaM+S9hHsgn4qhgMfXHVojvH5FOot9kqByU8LGgC7/n5N2f2gJk
		M8kZ+4KkqFL/7ovs6VF5lYbAHNm5vZvxBPNxomcda9ZUJHcUnVxHt9zcJMPrKrka
		TjKlksl4eEg9I5fnNk2uNT0asfMrT3oIuS+cB/0iBmLGylrMkrijYc6hQLBd7ip3
		WcG/mpOagBAdABLYRP/7AwYywQ+xqdog0DInoiWk08gLfRjQiKHzjAoQaHh6m/P4
		5tz5B+5uIFkD7kp2edWK7csqfUfX/45bEQO/TEGlTzjB0qMwrnU9lV5Pg7AEiEQ4
		BBKKPfhJAoGBAOMEbidto9D/EZLElY8itMotIdiCAqJTC4ClZ8+ayU0Oiq5wChfg
		/EeM7VUW7tMWFzYpBCNiKJ81QxWFDxeDvXReKR6ZZgxGdRjk7Y8HFeuszfnnRnYZ
		f3RMOdTkutu3gFHLcpWS2DRU1p2VnCc1kvIf15/TTlzcoUBKDFIkwW/tAoGBAO7z
		3tNwck2LJZ90F6bP3zm/X1PoZDOb6byxSyV1b4etxPiscFAVR5saKtQJa9N8y296
		7VQit0Qb2ZigJDKcSliZG7TkH0FcLM817oiC0zVVHD1cQUJ84p7qRtptfnINAvpA
		ARxPfmaTdM/jwaidXcF+gmouE4XPrS7EG7802FSzAoGAJDj7vozO+7UHP8zgNEOM
		Z0oGQX6VHwNzLWa3Brgi8ImmdSjpY2ABwQTqhY4wMzwuHfUzdNXft2+PMarWeqEJ
		pLy1gO1nDAReAMfeY9j0lXMwNnTBmGx/GrZi7+ZDLnW8ItD8ioMwvkDfMavCi7sP
		pFSSWi0kLssBa7mk96Jnvw0CgYEAmX74zZQ3KM7QzTwzEUoJGDxxzSHEdE6ceETf
		g+GLUnnyxNdoklkJFX5asriWllVdDXDG0bw3Q74sKln8xrIVJBK+dJXx6fd/JWB8
		qR549JKGwHfpx/8XSIQwHZImnrbzCbRhwkDibpwcdorU1S65klllBzYv/k4o7pi1
		Rj95E/cCgYEAzJdWkCcraSoHLormlaXLGp/oXpubRyM0JT/40pcotwXERpKOLaYK
		VYCew9XWz/TwYn2TawNnA4NPobBR/pdfV4xETWVRDfjKCw3XFBDv2gZsfxCD6YZH
		lvBRsv9yzqClpFvr6SI1gp04fcIXuzJS3miKtOSy+v6w/5Pp+UJCwCc=
		-----END RSA PRIVATE KEY-----`

				//block, _ := pem.Decode([]byte(pemString))
				//key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

		*/
		certToSign := []byte (pkiClientCert) //Self-Signed Cert
		hashToSign32bytes := sha256.Sum256(certToSign)
		clientCertHashToSign = hashToSign32bytes[:]


		/**
		signature, signError := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashedCert[:])

		if (signError != nil){
			logger.Debugf("Error while creating signature ", signError.Error())
		}


		clientCertEndorserSig := base64.StdEncoding.EncodeToString(signature)
		logger.Debugf("EndorserCertSignature: %v\n", clientCertEndorserSig)*/
	}

	// MIGUEL - END

	// handle simulation results
	var results []byte
	if args[5] == nil {
		return shim.Error("simulation results are null")
	}

	results = args[5]

	// Handle serialized events if they have been provided
	// they might be nil in case there's no events but there
	// is a visibility field specified as the next arg
	events := []byte("")
	if len(args) > 6 && args[6] != nil {
		events = args[6]
	}

	// Handle payload visibility (it's an optional argument)
	// currently the fabric only supports full visibility: this means that
	// there are no restrictions on which parts of the proposal payload will
	// be visible in the final transaction; this default approach requires
	// no additional instructions in the PayloadVisibility field; however
	// the fabric may be extended to encode more elaborate visibility
	// mechanisms that shall be encoded in this field (and handled
	// appropriately by the peer)
	var visibility []byte
	if len(args) > 7 {
		visibility = args[7]
	}

	// obtain the default signing identity for this peer; it will be used to sign this proposal response
	localMsp := mspmgmt.GetLocalMSP()
	if localMsp == nil {
		return shim.Error("Nil local MSP manager")
	}

	signingEndorser, err := localMsp.GetDefaultSigningIdentity()
	if err != nil {
		return shim.Error(fmt.Sprintf("Could not obtain the default signing identity, err %s", err))
	}



	// FGODINHO
	// if it's a system chaincode just go with multisig
	var currSigMethod []byte
	if ccid.GetName() == "lscc" || ccid.GetName() == "cscc" {
		currSigMethod = []byte("multisig")
	} else {
		sigMethodForCC := cCSigMethods[ccid.GetName()]
		if len(sigMethodForCC) > 0 {
			currSigMethod = sigMethodForCC
		} else {
			// compose chaincode args for get endorsement method
			ccargs := make([][]byte, 1, 1)
			ccargs[0] = []byte("getEndorsementMethod")

			// we call this function on any contract to find out its signing method and pass it to createproposalresponse
			sigMethodRsp := stub.InvokeChaincode(ccid.GetName(), ccargs, stub.GetChannelID())
			if sigMethodRsp.Status != 200 {
				return shim.Error(fmt.Sprintf("Could not obtain the endorsement method from contract %s on channel %s", ccid.GetName(), stub.GetChannelID()))
			}
			currSigMethod = sigMethodRsp.Payload
			cCSigMethods[ccid.GetName()] = currSigMethod // store for later
		}
	}

	// obtain a proposal response & MIGUEL (Changed CreateProposalResponse args to include if transaction is to sign certificate and hash of the certificate)
	presp, err := utils.CreateProposalResponse(hdr, payl, response, results, events, ccid, visibility, signingEndorser, currSigMethod, transactionToSignCertificate, clientCertHashToSign)
	if err != nil {
		return shim.Error(err.Error())
	}

	logger.Debug("AAA1")

	// /FGODINHO

	// marshall the proposal response so that we return its bytes
	prBytes, err := utils.GetBytesProposalResponse(presp)
	if err != nil {
		return shim.Error(fmt.Sprintf("Could not marshal ProposalResponse: err %s", err))
	}

	logger.Debug("AAA2")

	pResp, err := utils.GetProposalResponse(prBytes)
	if err != nil {
		return shim.Error(err.Error())
	}
	logger.Debug("AAA3")
	if pResp.Response == nil {
		fmt.Println("GetProposalResponse get empty Response")
	}

	logger.Debugf("ESCC exits successfully")
	return shim.Success(prBytes)
}
