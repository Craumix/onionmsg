package generator

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"regexp"

	"github.com/craumix/onionmsg/internal/types"
)

type GeneratorThread struct {
	Counter uint64

	ctx         context.Context
	nextKeyChan chan ed25519.PrivateKey
	regex       *regexp.Regexp
}

func CreateGeneratorThread(ctx context.Context, nextKey chan ed25519.PrivateKey, regex *regexp.Regexp) GeneratorThread {
	return GeneratorThread{
		ctx:         ctx,
		nextKeyChan: nextKey,
		regex:       regex,
	}
}

func (t *GeneratorThread) Start() {
	go func() {
		for t.ctx.Err() == nil {

			pub, priv, err := ed25519.GenerateKey(nil)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fingerprint := types.FingerprintKeyFormatting(pub)
			if t.regex.MatchString(fingerprint) {
				t.nextKeyChan <- priv
			}

			t.Counter++
		}
	}()
}
