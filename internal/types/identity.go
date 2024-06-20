package types

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/wybiral/torgo"
)

type IdentityType string

const (
	Remote  IdentityType = "RemoteIdentity"
	Self    IdentityType = "SelfIdentity"
	Contact IdentityType = "ContactIdentity"
)

type IdentityMeta struct {
	Nick  string `json:"nick"`
	Admin bool   `json:"admin"`
}

type Identity struct {
	Type IdentityType `json:"type"`

	Priv *ed25519.PrivateKey `json:"priv,omitempty"`
	Pub  *ed25519.PublicKey  `json:"pub,omitempty"`

	Meta *IdentityMeta `json:"meta,omitempty"`
}

func NewIdentity(iType IdentityType, fingerprint string) (Identity, error) {
	i := Identity{
		Type: iType,
	}

	switch iType {
	case Remote:
		err := i.fillPublicKey(fingerprint)
		if err != nil {
			return Identity{}, err
		}
	case Self, Contact:
		i.fillKeyPair()
	}

	switch iType {
	case Remote, Self:
		i.Meta = &IdentityMeta{}
	}

	return i, nil
}

func (i *Identity) fillPublicKey(fingerprint string) error {
	raw, err := base64.RawURLEncoding.DecodeString(fingerprint)
	if err != nil {
		return err
	}

	pubKey := ed25519.PublicKey(raw)

	i.Pub = &pubKey

	return nil
}

func (i *Identity) fillKeyPair() {
	_, privKey, _ := ed25519.GenerateKey(nil)

	pubKey := privKey.Public().(ed25519.PublicKey)

	i.Priv = &privKey
	i.Pub = &pubKey
}

func (i Identity) Sign(data []byte) ([]byte, error) {
	if i.Priv == nil {
		return nil, fmt.Errorf("no private key")
	}

	return ed25519.Sign(*i.Priv, data), nil
}

func (i Identity) Verify(msg, sig []byte) (bool, error) {
	if i.Pub == nil {
		return false, fmt.Errorf("no public key")
	}

	return ed25519.Verify(*i.Pub, msg, sig), nil
}

func (i Identity) IsType(toCheck ...IdentityType) bool {
	for _, iType := range toCheck {
		if i.Type == iType {
			return true
		}
	}

	return false
}

func (i Identity) Fingerprint() string {
	if i.Pub == nil {
		return ""
	}

	return FingerprintKeyFormatting(*i.Pub)
}

func FingerprintKeyFormatting(pub ed25519.PublicKey) string {
	if pub == nil {
		return ""
	}

	return base64.RawURLEncoding.EncodeToString(pub)
}

func (i Identity) String() string {
	return fmt.Sprintf("%s: %s", i.Type, i.Fingerprint())
}

func (i Identity) URL() string {
	return i.ServiceID() + ".onion"
}

func (i Identity) ServiceID() string {
	if i.Pub == nil {
		return ""
	}

	id, _ := torgo.ServiceIDFromEd25519(*i.Pub)
	return id
}

func (i Identity) Admin() bool {
	if i.Meta == nil {
		return false
	}

	return i.Meta.Admin
}

func (i Identity) Nick() string {
	if i.Meta == nil {
		return ""
	}

	return i.Meta.Nick
}
