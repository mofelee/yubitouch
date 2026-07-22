package ageprofile

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// EncodeNativeRecipient returns a canonical native age X25519 recipient, or
// an empty string if the public key is invalid.
func EncodeNativeRecipient(publicKey PublicKey) string {
	if err := validatePublicKey(publicKey); err != nil {
		return ""
	}
	key, err := ecdh.X25519().NewPublicKey(publicKey[:])
	if err != nil {
		return ""
	}
	encoded, err := plugin.EncodeX25519Recipient(key)
	if err != nil {
		return ""
	}
	return encoded
}

// ParseNativeRecipient parses a canonical native age X25519 recipient and
// returns its raw public key.
func ParseNativeRecipient(s string) (PublicKey, error) {
	native, err := age.ParseX25519Recipient(s)
	if err != nil {
		return PublicKey{}, errors.New("invalid native age X25519 recipient")
	}
	if native.String() != s {
		return PublicKey{}, errors.New("native age X25519 recipient is not canonical")
	}
	hrp, payload, err := decodeBech32(s)
	if err != nil || hrp != "age" || len(payload) != len(PublicKey{}) {
		return PublicKey{}, errors.New("invalid native age X25519 recipient encoding")
	}
	var publicKey PublicKey
	copy(publicKey[:], payload)
	if err := validatePublicKey(publicKey); err != nil {
		return PublicKey{}, errors.New("invalid native age X25519 public key")
	}
	if EncodeNativeRecipient(publicKey) != s {
		return PublicKey{}, errors.New("native age X25519 recipient is not canonical")
	}
	return publicKey, nil
}

// ParseNativeIdentity parses a canonical native age X25519 identity into a
// software private key. Errors never include the identity text or key bytes.
func ParseNativeIdentity(s string) (*ecdh.PrivateKey, error) {
	native, err := age.ParseX25519Identity(s)
	if err != nil {
		return nil, errors.New("invalid native age X25519 identity")
	}
	if native.String() != s {
		return nil, errors.New("native age X25519 identity is not canonical")
	}
	hrp, payload, err := decodeBech32(s)
	if err != nil || hrp != "AGE-SECRET-KEY-" || len(payload) != 32 {
		return nil, errors.New("invalid native age X25519 identity encoding")
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(payload)
	clear(payload)
	if err != nil {
		return nil, errors.New("invalid native age X25519 private key")
	}
	publicBytes := privateKey.PublicKey().Bytes()
	if len(publicBytes) != len(PublicKey{}) {
		return nil, errors.New("invalid derived X25519 public key")
	}
	var publicKey PublicKey
	copy(publicKey[:], publicBytes)
	if EncodeNativeRecipient(publicKey) != native.Recipient().String() {
		return nil, errors.New("native age identity public key derivation mismatch")
	}
	return privateKey, nil
}

// The Bech32 decoder below is derived from the BIP173 reference implementation
// as modified by the age project.
//
// Copyright (c) 2017 Takatoshi Nakagawa
// Copyright (c) 2019 The age Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Generator = [...]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func decodeBech32(s string) (string, []byte, error) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, errors.New("mixed case Bech32 encoding")
	}
	separator := strings.LastIndexByte(s, '1')
	if separator < 1 || separator+7 > len(s) {
		return "", nil, errors.New("invalid Bech32 separator")
	}
	hrp := s[:separator]
	for _, char := range hrp {
		if char < 33 || char > 126 {
			return "", nil, errors.New("invalid Bech32 human-readable part")
		}
	}
	lower := strings.ToLower(s)
	values := make([]byte, 0, len(lower)-separator-1)
	for _, char := range lower[separator+1:] {
		value := strings.IndexRune(bech32Charset, char)
		if value < 0 {
			return "", nil, errors.New("invalid Bech32 data character")
		}
		values = append(values, byte(value))
	}
	if bech32Polymod(append(bech32HRPExpand(hrp), values...)) != 1 {
		return "", nil, errors.New("invalid Bech32 checksum")
	}
	payload, err := convertBech32Bits(values[:len(values)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, payload, nil
}

func bech32Polymod(values []byte) uint32 {
	check := uint32(1)
	for _, value := range values {
		top := check >> 25
		check = (check & 0x1ffffff) << 5
		check ^= uint32(value)
		for i := range bech32Generator {
			if top>>i&1 == 1 {
				check ^= bech32Generator[i]
			}
		}
	}
	return check
}

func bech32HRPExpand(hrp string) []byte {
	hrp = strings.ToLower(hrp)
	result := make([]byte, 0, len(hrp)*2+1)
	for _, char := range hrp {
		result = append(result, byte(char>>5))
	}
	result = append(result, 0)
	for _, char := range hrp {
		result = append(result, byte(char&31))
	}
	return result
}

func convertBech32Bits(data []byte, fromBits, toBits byte, pad bool) ([]byte, error) {
	var result []byte
	var accumulator uint32
	var bits byte
	maxValue := byte(1<<toBits - 1)
	for index, value := range data {
		if value>>fromBits != 0 {
			return nil, fmt.Errorf("invalid Bech32 value at index %d", index)
		}
		accumulator = accumulator<<fromBits | uint32(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, byte(accumulator>>bits)&maxValue)
		}
	}
	if pad {
		if bits > 0 {
			result = append(result, byte(accumulator<<(toBits-bits))&maxValue)
		}
	} else if bits >= fromBits {
		return nil, errors.New("illegal Bech32 zero padding")
	} else if byte(accumulator<<(toBits-bits))&maxValue != 0 {
		return nil, errors.New("non-zero Bech32 padding")
	}
	return result, nil
}
