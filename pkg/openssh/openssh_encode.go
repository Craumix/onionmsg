package openssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"log"
)

func EncodeToPemBytes(key ed25519.PrivateKey) []byte {
	buffer := new(bytes.Buffer)

	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: EncodeToBytes(key),
	}
	pem.Encode(buffer, block)

	return buffer.Bytes()
}

//TODO key format not yet properly accepted by OpenSSH.
//Struture seems to be fine, yet the specific Pub/Priv-Key bytes,
//are wrongly formatted. (Altough I'm not sure how else you would format them ??)
func EncodeToBytes(key ed25519.PrivateKey) []byte {
	buffer := new(bytes.Buffer)

	//ASCII magic "openssh-key-v1" plus null byte
	buffer.WriteString("openssh-key-v1")
	buffer.WriteByte(0x00)

	//Cipher
	buffer.Write(intToBytes(4))
	buffer.WriteString("none")

	//KDFName
	buffer.Write(intToBytes(4))
	buffer.WriteString("none")

	//KDF Iters (?)
	buffer.Write(intToBytes(0))

	//Number of Public-Keys
	buffer.Write(intToBytes(1))

	//Length of first PublicKey
	buffer.Write(intToBytes(4 + 11 + 4 + 32))

	//Key type
	buffer.Write(intToBytes(11))
	buffer.WriteString("ssh-ed25519")

	//Public-Key
	buffer.Write(intToBytes(32))
	buffer.Write(key.Public().(ed25519.PublicKey))

	//Payload length
	buffer.Write(intToBytes(8 + 4 + 11 + 4 + 32 + 4 + 64 + 4 + 5))

	//Check bytes (random ?) (If Checksum FIX!!!)
	check := make([]byte, 4)
	c, err := rand.Read(check)
	if c != len(check) || err != nil {
		log.Printf("Read %d bytes should be %d", c, len(check))
		log.Fatal(err)
	}
	buffer.Write(check)
	buffer.Write(check)

	//Key type
	buffer.Write(intToBytes(11))
	buffer.WriteString("ssh-ed25519")

	//Public-Key
	buffer.Write(intToBytes(32))
	buffer.Write(key.Public().(ed25519.PublicKey))

	//Private-Key
	buffer.Write(intToBytes(64))
	buffer.Write(key)

	//Zero length comment
	buffer.Write(intToBytes(0))

	//Padding
	buffer.Write(incPadding(5))

	return buffer.Bytes()
}

func incPadding(lenght int) []byte {
	p := make([]byte, lenght)

	for i := 0; i < lenght; i++ {
		p[i] = uint8(i + 1)
	}

	return p
}

func intToBytes(i int) []byte {
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(i))
	return bs
}
