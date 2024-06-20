package generator

import (
	"context"
	"crypto/ed25519"
	"regexp"
	"time"
)

type GeneratorOptions struct {
	Threads     int
	Count       int
	Regex       *regexp.Regexp
	TickTimeout time.Duration
	DidTick     func(time.Time, ed25519.PrivateKey, int, uint64)
	Ctx         context.Context
}

func DefaultGeneratorOpts() GeneratorOptions {
	return GeneratorOptions{
		Threads:     1,
		Count:       1,
		Regex:       &regexp.Regexp{},
		TickTimeout: time.Hour * 24 * 365,
		Ctx:         context.Background(),
	}
}

func GenerateIdentities(opts GeneratorOptions) []ed25519.PrivateKey {
	if opts.Ctx == nil {
		opts.Ctx = context.Background()
	}

	nextKeyChan := make(chan ed25519.PrivateKey)
	keys := make([]ed25519.PrivateKey, 0)
	ctx, cancel := context.WithCancel(opts.Ctx)
	threads := setupThreads(opts.Threads, ctx, nextKeyChan, opts.Regex)

	startTime := time.Now()
	var lastKey ed25519.PrivateKey
	for ctx.Err() == nil {
		var count uint64
		for _, thread := range threads {
			if lastKey != nil && (len(keys) == 0 || !lastKey.Equal(keys[len(keys)-1])) {
				keys = append(keys, lastKey)
			}
			count += thread.Counter

			if opts.DidTick != nil {
				opts.DidTick(startTime, lastKey, len(keys), count)
			}

			if len(keys) >= opts.Count {
				cancel()
			}
		}

		select {
		case lastKey = <-nextKeyChan:
		case <-ctx.Done():
		case <-time.After(opts.TickTimeout):
		}
	}

	return keys
}

func setupThreads(count int, threadCtx context.Context, nextKeyChan chan ed25519.PrivateKey, regex *regexp.Regexp) []GeneratorThread {
	threads := make([]GeneratorThread, count)

	for i := 0; i < count; i++ {
		threads[i] = CreateGeneratorThread(threadCtx, nextKeyChan, regex)
		threads[i].Start()
	}

	return threads
}
