package openssh

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

func DecodeFromFile(filename, password string) (ed25519.PrivateKey, error) {
	pemBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return DecodeFromPem(pemBytes, password)
}

func DecodeFromPem(pemBytes []byte, password string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("unable to get pem block")
	}

	return DecodeFromBytes(block.Bytes, password)
}

func DecodeFromBytes(raw []byte, password string) (ed25519.PrivateKey, error) {
	magicNullterm := bytes.Index(raw, []byte{0x00})
	authMagic := string(raw[:magicNullterm])
	raw = raw[magicNullterm+1:]
	if authMagic != "openssh-key-v1" {
		return nil, fmt.Errorf("invalid auth magic %s", authMagic)
	}

	raw, ciphername := readNextString(raw)
	raw, kdfname := readNextString(raw)
	raw, kdfopts := readNextBytes(raw)
	raw, num := readNextInt(raw)
	if num != 0x01 {
		return nil, fmt.Errorf("invalid value for number of keys %d", num)
	}

	//Skip Public-Key length
	raw = raw[4:]

	//Skip Public Key
	raw, _ = readNextString(raw)
	raw, _ = readNextBytes(raw)

	raw, payloadSize := readNextInt(raw)

	if ciphername == "none" && kdfname == "none" {
		return keyFromPayload(raw[:payloadSize])
	} else if kdfname == "bcrypt" {
		/*
			For reference:
			https://peterlyons.com/problog/2017/12/openssh-ed25519-private-key-file-format/
			https://crypto.stackexchange.com/questions/58536/how-does-openssh-use-bcrypt-to-set-ivs
			https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD
			https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/sshkey.c?rev=1.64&content-type=text/x-cvsweb-markup&only_with_tag=MAIN
		*/

		salt := kdfopts[4:20]
		rounds := kdfopts[20:24]
		log.Println(salt)
		log.Println(rounds)
		return nil, fmt.Errorf("encrypted keys are currently not supported")
	} else {
		return nil, fmt.Errorf("unable to decrypt cipher %s with kdf %s", ciphername, kdfname)
	}
}

func keyFromPayload(payload []byte) (ed25519.PrivateKey, error) {
	payload, checkint1 := readNextInt(payload)
	payload, checkint2 := readNextInt(payload)
	if checkint1 != checkint2 {
		return nil, fmt.Errorf("checkints don't match (key probably wrong)")
	}

	payload, keytype := readNextString(payload)
	if keytype != "ssh-ed25519" {
		return nil, fmt.Errorf("key is not of type ssh-ed25519 but of %s", keytype)
	}

	//Skip what is probably a duplicate of the public key
	payload, _ = readNextBytes(payload)

	payload, privatekey := readNextBytes(payload)
	if len(privatekey) != 64 {
		return nil, fmt.Errorf("length of private key is not 64 but %d", len(privatekey))
	}

	//Comment
	_, _ = readNextString(payload)

	return ed25519.PrivateKey(privatekey), nil
}

func readNextInt(raw []byte) (newRaw []byte, length int) {
	length = int(binary.BigEndian.Uint32(raw[:4]))
	newRaw = raw[4:]
	return
}

func readNextBytes(raw []byte) (newRaw, value []byte) {
	raw, length := readNextInt(raw)
	value = raw[:length]
	newRaw = raw[length:]
	return
}

func readNextString(raw []byte) (newRaw []byte, value string) {
	newRaw, tmp := readNextBytes(raw)
	value = string(tmp)
	return
}
