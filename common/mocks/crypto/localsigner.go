/*
Copyright IBM Corp. 2017 All Rights Reserved.

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

package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	cb "github.com/hyperledger/fabric/protos/common"
)

// FakeLocalSigner is a signer which already has identity an nonce set to fake values
var FakeLocalSigner = &LocalSigner{
	Identity: []byte("IdentityBytes"),
	Nonce:    []byte("NonceValue"),
}

// LocalSigner is a mock implementation of crypto.LocalSigner
type LocalSigner struct {
	Identity []byte
	Nonce    []byte
}

// Sign returns the msg, nil
func (ls *LocalSigner) Sign(msg []byte) ([]byte, error) {

	// FGODINHO/
	mockShare := "AAAAAQAAAJAMVssN0DYN8YCDQI2zBEPNgDypiq+xRCpQS4dISjzpN2xa8mUBshUgeKl6zHIJpRancLbiFXoh6i/bMC5iRRqsVXh6od11NWBMx6lhq4QCjGM7GEiNghkEoBL5pF6Qlnwy2Oh0nOyu7n/n9c/3YaABAWVdldmPWWLgoFFgMeL+2B8K0xhCqJ6WjFC2VLCQr3QAAACAXJAPiQQVmP1Vcbkg9jNzylOh6TSqvgmkP/Ywql9of9waEBg6EydMoFqiZUsFAq5GJemP8ztyNNdNELCSStNzaMcr198Yz8IRPKjuF2VHQqnj08sKvuWEvgeuyLjJV+u7OScZM8wmyb74usfVSE/6WC3VnjsLQC1btDxGjBNkfq0AAAACAtAAAACARi7NSP/svwt9K6vkuJOKgjdfe0UDFc3qGX4b+uTtkWytOC9GAlRV7YCSeY0YZg5IBfzvf9nuEiL55gxqiDk/9O5G0T1a6bLMxIPsK6tML3KVzRwc4kA4w6DraQAIqVXGhbB/QjvHVqFuATCT+PPpWGVNFsDwjtH3EcQfLuXpie0AAACAMl3/2LGK3BmEzEQoWc+ejD4xLPuwo7KpLkAdjl5eIpKN1WNj4GIH/oQqBG3+NmqG9HlqBsNl0zrVk6n3CJZcaSJm2qI4tfKSQG6h4E/E6Q3Vtc+1TdGRXftLBBSD0l//F3p+iYXprZRlOGGkopJ02wPbSg+unFP9cpLwqMJOWmM="

	// open unix domain socket connection
	conn, err := net.Dial("unix", "/tmp/hlf-xsp.sock")
	if err != nil {
		panic(fmt.Sprintf("Could not start connection pool to java component: %s", err))
	}

	// defer connection for closing after sing concludes
	defer conn.Close()

	// send away the call
	//payload := "__CALL_THRESHSIG_DEAL\n{\"l\":8,\"k\":5,\"key-size\":512}"
	//payload := "__CALL_THRESHSIG_DEAL\n{\"l\":8,\"k\":5,\"key-size\":512}"
	var bufferWr bytes.Buffer

	bufferWr.WriteString("__CALL_THRESHSIG_SIGN\n")
	bufferWr.WriteString("{\"share\":\"")
	bufferWr.WriteString(mockShare)
	bufferWr.WriteString("\",\"msg\":\"")
	bufferWr.WriteString(string(msg))
	bufferWr.WriteString("\"}")

	payload := bufferWr.String()
	_, err = conn.Write([]byte(payload))

	if err != nil {
		panic(fmt.Sprintf("Unable to send payload to java component for signing: %s", err))
	}

	bufferRd := make([]byte, 1024)
	nr, err := conn.Read(bufferRd)
	if err != nil {
		panic(fmt.Sprintf("Unable to read payload from java component: %s", err))
	}

	// break the response into its parts
	response := strings.Split(string(bufferRd[:nr]), "\n")

	// check the call
	if response[0] != "__RETU_THRESHSIG_SIGN" {
		panic(fmt.Sprintf("Wrong response from java component: %s", response[0]))
	}

	// parse the payload into a json
	type SigMsg struct {
		Id        int    `json:"id"`
		Signature string `json:"signature"`
	}

	var sigma SigMsg
	err = json.Unmarshal([]byte(response[1]), &sigma)
	if err != nil {
		panic(fmt.Sprintf("Unable to parse payload from java component: %s", err))
	}

	return []byte(sigma.Signature), nil
	// return msg, nil
	// /FGODINHO

}

// NewSignatureHeader returns a new signature header, nil
func (ls *LocalSigner) NewSignatureHeader() (*cb.SignatureHeader, error) {
	return &cb.SignatureHeader{
		Creator: ls.Identity,
		Nonce:   ls.Nonce,
	}, nil
}
