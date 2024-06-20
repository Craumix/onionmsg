package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/craumix/onionmsg/pkg/generator"
	"github.com/craumix/onionmsg/pkg/openssh"
	"github.com/craumix/onionmsg/internal/types"
)

const (
	ups = 2
	warning = "The Content of this file is VERY sensitive!\nAll the keys here are UNENCRYPTED!\nIf you are using any of these keys, don't share them with ANYONE!\n"
)

var (
	match    = ""
	count    = 10
	threads  = runtime.NumCPU()
	anywhere = false
	format   = "base64"
	nowarn   = false
	file     = ""

	err error
)

func main() {
	flag.StringVar(&match, "m", match, "Specify a filter to match")
	flag.BoolVar(&anywhere, "a", anywhere, "Matches anywhere (not just at the start)")
	flag.IntVar(&count, "c", count, "Specify an amount of Identities to generate")
	flag.IntVar(&threads, "t", threads, "Number of threads")
	flag.StringVar(&format, "form", format, "The output format for the keys ( base64 / openssh / hex )")
	flag.BoolVar(&nowarn, "nw", nowarn, "No warning above output")
	flag.StringVar(&file, "f", file, "Output file")
	flag.Parse()

	//Save cursor position & hide it
	fmt.Print("\033[s\033[?25l")
	//Show cursor position on exit
	defer fmt.Print("\033[?25h")
	func(){
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			fmt.Print("\033[?25h")
			os.Exit(0)
		}()
	}()
	
	if !anywhere && !strings.HasPrefix(match, "^") {
		match = "^" + match
	}

	keys := generator.GenerateIdentities(generator.GeneratorOptions{
		Threads:     threads,
		Count:       count,
		Regex:       regexp.MustCompile(match),
		TickTimeout: time.Second / ups,
		DidTick: func(t time.Time, pk ed25519.PrivateKey, i int, j uint64) {
			lastFP := ""
			if pk != nil {
				lastFP = types.FingerprintKeyFormatting(pk.Public().(ed25519.PublicKey))
			}

			var keysPerSecondPerThread time.Duration = 0
			if j > 0 {
				keysPerThread := float64(j) / float64(threads)
				keysPerSecondPerThread = time.Duration(keysPerThread / float64(time.Since(t)/time.Second))
			}
			if keysPerSecondPerThread < 0 {
				keysPerSecondPerThread = 0
			}

			//Load cursor position
			fmt.Print("\033[u")
			fmt.Printf("Progress: [%d/%d] %d\033[K\n", i, count, j)
			fmt.Printf("Time elapsed: %s\033[K\n", time.Since(t))
			fmt.Printf("Speed: avg. %d keys / second / thread\033[K\n", keysPerSecondPerThread)
			fmt.Printf("Last: %s\033[K\n", lastFP)

		},
	})

	fmt.Println()

	keyout := os.Stdout
	if file != "" {
		keyout, err = os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Println(err)
			keyout = os.Stdout
		}

		if keyout != os.Stdout {
			defer keyout.Close()
		}
	}

	outputKeys(keys, keyout, format, !nowarn)
}

func outputKeys(keys []ed25519.PrivateKey, out *os.File, format string, warn bool) {
	if warn {
		out.WriteString(warning + "\n")
	}

	for _, k := range keys {
		out.WriteString("Fingerprint: " + types.FingerprintKeyFormatting(k.Public().(ed25519.PublicKey)) + "\n")
		out.WriteString("Key:\n" + formatKey(k, format) + "\n\n")
	}
}

func formatKey(key ed25519.PrivateKey, format string) string {
	switch(format) {
	case "openssh":
		return string(openssh.EncodeToPemBytes(key))
	case "hex":
		return hex.EncodeToString(key)
	default:
		return base64.StdEncoding.EncodeToString(key)
	}
}