package sw

// FGODINHO/

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/hyperledger/fabric/bccsp"
)

type xspSignMsg struct {
	Id        int    `json:"id"`
	Signature string `json:"signature"`
}

type xspVerifyMsg struct {
	Valid bool `json:"valid"`
}

type threshSigner struct{}

func (s *threshSigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {

	shareBytes := k.(*threshRsaKeyShare).KeyShareBytes

	// open unix domain socket connection
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
	bufferRd := make([]byte, 1024)
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

type threshVerifier struct{}

func (v *threshVerifier) Verify(k bccsp.Key, signatures [][]byte, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {

	groupKeyBytes := k.(*threshRsaGroupKey).groupKey.GroupKeyBytes

	// open unix domain socket connection
	conn, err := net.Dial("unix", "/tmp/hlf-xsp.sock")
	if err != nil {
		return false, fmt.Errorf("Could not start connection pool to java component: %s", err)
	}

	// defer connection for closing after sing concludes
	defer conn.Close()

	// send away the call
	var bufferWr bytes.Buffer
	bufferWr.WriteString("__CALL_THRESHSIG_VERI\n")
	bufferWr.WriteString("{\"group-key\":\"")
	bufferWr.WriteString(string(groupKeyBytes))
	bufferWr.WriteString("\",\"signatures\":[")
	for ix, sig := range signatures {
		bufferWr.WriteString("\"")
		bufferWr.WriteString(string(sig))
		bufferWr.WriteString("\"")
		if ix < len(signatures)-1 {
			bufferWr.WriteString(",")
		}
	}
	bufferWr.WriteString("],\"msg\":\"")
	bufferWr.WriteString(string(digest))
	bufferWr.WriteString("\"}")
	payload := bufferWr.String()
	_, err = conn.Write([]byte(payload))

	if err != nil {
		return false, fmt.Errorf("Unable to send payload to java component for verification: %s", err)
	}

	// read response from socket
	bufferRd := make([]byte, 1024)
	nr, err := conn.Read(bufferRd)
	if err != nil {
		return false, fmt.Errorf("Unable to read payload from java component: %s", err)
	}

	// break the response into its parts
	response := strings.Split(string(bufferRd[:nr]), "\n")

	// check the call
	if response[0] != "__RETU_THRESHSIG_VERI" {
		return false, fmt.Errorf("Wrong response from java component: %s", response[0])
	}

	// parse verify result
	var delta xspVerifyMsg
	err = json.Unmarshal([]byte(response[1]), &delta)
	if err != nil {
		return false, fmt.Errorf("Unable to parse payload from java component: %s", err)
	}

	return delta.Valid, nil
}
