package sw

// FGODINHO/

import (
	"errors"

	"github.com/hyperledger/fabric/bccsp"
)

// threshRsaGroupKey and threshRsaKeyShareASN reflect the ASN.1 structure of a Victor Shoup's Threshold group key and key share respectively
type threshRsaGroupKeyASN struct {
	K             int
	L             int
	GroupKeyBytes []byte
}

type threshRsaKeyShare struct {
	Id            int
	KeyShareBytes []byte
	GroupKey      *threshRsaGroupKeyASN
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *threshRsaKeyShare) Bytes() (raw []byte, err error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *threshRsaKeyShare) SKI() (ski []byte) {
	return nil
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *threshRsaKeyShare) Symmetric() bool {
	return false
}

// Private returns true if this key is an asymmetric private key,
// false otherwise.
func (k *threshRsaKeyShare) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *threshRsaKeyShare) PublicKey() (bccsp.Key, error) {
	return &threshRsaGroupKey{k.GroupKey}, nil
}

type threshRsaGroupKey struct {
	groupKey *threshRsaGroupKeyASN
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *threshRsaGroupKey) Bytes() (raw []byte, err error) {
	if k.groupKey == nil {
		return nil, errors.New("Failed marshalling key. Key is nil.")
	}
	raw = k.groupKey.GroupKeyBytes
	return raw, nil
}

// SKI returns the subject key identifier of this key.
func (k *threshRsaGroupKey) SKI() (ski []byte) {
	return nil
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *threshRsaGroupKey) Symmetric() bool {
	return false
}

// Private returns true if this key is an asymmetric private key,
// false otherwise.
func (k *threshRsaGroupKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *threshRsaGroupKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
