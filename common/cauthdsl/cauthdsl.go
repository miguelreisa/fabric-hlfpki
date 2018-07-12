/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cauthdsl

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/msp"
	cb "github.com/hyperledger/fabric/protos/common"
	mb "github.com/hyperledger/fabric/protos/msp"

	"github.com/op/go-logging"
)

var cauthdslLogger = flogging.MustGetLogger("cauthdsl")

// deduplicate removes any duplicated identities while otherwise preserving identity order
func deduplicate(sds []*cb.SignedData, deserializer msp.IdentityDeserializer) []*cb.SignedData {
	ids := make(map[string]struct{})
	result := make([]*cb.SignedData, 0, len(sds))
	for i, sd := range sds {
		identity, err := deserializer.DeserializeIdentity(sd.Identity)
		if err != nil {
			cauthdslLogger.Errorf("Principal deserialization failure (%s) for identity %x", err, sd.Identity)
			continue
		}
		key := identity.GetIdentifier().Mspid + identity.GetIdentifier().Id

		if _, ok := ids[key]; ok {
			cauthdslLogger.Warningf("De-duplicating identity %x at index %d in signature set", sd.Identity, i)
		} else {
			result = append(result, sd)
			ids[key] = struct{}{}
		}
	}
	return result
}

// compile recursively builds a go evaluatable function corresponding to the policy specified, remember to call deduplicate on identities before
// passing them to this function for evaluation
func compile(policy *cb.SignaturePolicy, identities []*mb.MSPPrincipal, deserializer msp.IdentityDeserializer) (func([]*cb.SignedData, []bool) bool, error) {
	if policy == nil {
		return nil, fmt.Errorf("Empty policy element")
	}

	switch t := policy.Type.(type) {
	case *cb.SignaturePolicy_NOutOf_:
		policies := make([]func([]*cb.SignedData, []bool) bool, len(t.NOutOf.Rules))
		for i, policy := range t.NOutOf.Rules {
			compiledPolicy, err := compile(policy, identities, deserializer)
			if err != nil {
				return nil, err
			}
			policies[i] = compiledPolicy

		}
		return func(signedData []*cb.SignedData, used []bool) bool {
			grepKey := time.Now().UnixNano()
			cauthdslLogger.Debugf("%p gate %d evaluation starts", signedData, grepKey)
			verified := int32(0)
			_used := make([]bool, len(used))
			for _, policy := range policies {
				copy(_used, used)
				if policy(signedData, _used) {
					verified++
					copy(used, _used)
				}
			}

			if verified >= t.NOutOf.N {
				cauthdslLogger.Debugf("%p gate %d evaluation succeeds", signedData, grepKey)
			} else {
				cauthdslLogger.Debugf("%p gate %d evaluation fails", signedData, grepKey)
			}

			return verified >= t.NOutOf.N
		}, nil
	case *cb.SignaturePolicy_SignedBy:
		if t.SignedBy < 0 || t.SignedBy >= int32(len(identities)) {
			return nil, fmt.Errorf("identity index out of range, requested %v, but identies length is %d", t.SignedBy, len(identities))
		}
		signedByID := identities[t.SignedBy]
		return func(signedData []*cb.SignedData, used []bool) bool {
			cauthdslLogger.Debugf("%p signed by %d principal evaluation starts (used %v)", signedData, t.SignedBy, used)

			principalEvalResult := false
			signatures := make([][]byte, 0, len(signedData))
			for i, sd := range signedData {
				if used[i] {
					cauthdslLogger.Debugf("%p skipping identity %d because it has already been used", signedData, i)
					continue
				}
				if cauthdslLogger.IsEnabledFor(logging.DEBUG) {
					// Unlike most places, this is a huge print statement, and worth checking log level before create garbage
					cauthdslLogger.Debugf("%p processing identity %d with bytes of %x", signedData, i, sd.Identity)
				}
				identity, err := deserializer.DeserializeIdentity(sd.Identity)
				if err != nil {
					cauthdslLogger.Errorf("Principal deserialization failure (%s) for identity %x", err, sd.Identity)
					continue
				}
				err = identity.SatisfiesPrincipal(signedByID)
				if err != nil {
					cauthdslLogger.Debugf("%p identity %d does not satisfy principal: %s", signedData, i, err)
					continue
				}
				cauthdslLogger.Debugf("%p principal matched by identity %d", signedData, i)

				// FGODINHO TODO: Uncomment this. This makes no sense for thresh sig, but it does for multisig
				// err = identity.Verify(sd.Data, sd.Signature)
				// if err != nil {
				// 	cauthdslLogger.Debugf("%p signature for identity %d is invalid: %s", signedData, i, err)
				// 	continue
				// }
				signatures = append(signatures, sd.Signature)
				// /FGODINHO

				cauthdslLogger.Debugf("%p principal evaluation succeeds for identity %d", signedData, i)
				used[i] = true
				principalEvalResult = true
			}
			// FGODINHO
			if !principalEvalResult {
				cauthdslLogger.Debugf("%p principal evaluation fails", signedData)
			}

			// if len(signatures) > 0 {
			// 	var err error
			// 	if len(signatures) == 1 {
			// 		// not a thresh
			// 		identity, _ := deserializer.DeserializeIdentity(signedData[0].Identity)
			// 		err = identity.Verify(signedData[0].Data, signedData[0].Signature)
			// 	} else {
			// 		err = verifyThresh(signatures, signedData[0].Data)
			// 	}

			// 	if err != nil {
			// 		cauthdslLogger.Errorf("Error evaluating signatures: %s", err)
			// 	}
			// }
			// /FGODINHO

			return principalEvalResult
		}, nil
	default:
		return nil, fmt.Errorf("Unknown type: %T:%v", t, t)
	}
}

type xspVerifyMsg struct {
	Valid bool `json:"valid"`
}

func verifyThresh(signatures [][]byte, msg []byte) (err error) {

	// first hash the msg
	hasher := sha1.New()
	hasher.Write(msg)
	digest := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	groupKeyEnvVar, isSet := os.LookupEnv("THRESH_SIG_GROUP_KEY")
	if !isSet {
		return fmt.Errorf("Could not obtain key share from environment variable: THRESH_SIG_GROUP_KEY")
	}

	groupKeyBytes := []byte(groupKeyEnvVar)

	// open unix domain socket connection
	conn, err := net.Dial("unix", "/tmp/hlf-xsp.sock")
	if err != nil {
		return fmt.Errorf("Could not start connection pool to java component: %s", err)
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
		return fmt.Errorf("Unable to send payload to java component for verification: %s", err)
	}

	// read response from socket
	bufferRd := make([]byte, 1024)
	nr, err := conn.Read(bufferRd)
	if err != nil {
		return fmt.Errorf("Unable to read payload from java component: %s", err)
	}

	// break the response into its parts
	response := strings.Split(string(bufferRd[:nr]), "\n")

	// check the call
	if response[0] != "__RETU_THRESHSIG_VERI" {
		return fmt.Errorf("Wrong response from java component: %s", response[0])
	}

	// parse verify result
	var delta xspVerifyMsg
	err = json.Unmarshal([]byte(response[1]), &delta)
	if err != nil {
		return fmt.Errorf("Unable to parse payload from java component: %s", err)
	}

	if !delta.Valid {
		return fmt.Errorf("Verification of threshold signature failed")
	}
	return nil
}
