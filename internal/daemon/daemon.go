package daemon

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/craumix/onionmsg/internal/tor"
	"github.com/craumix/onionmsg/pkg/blobmngr"
	"github.com/craumix/onionmsg/pkg/sio"
	"github.com/craumix/onionmsg/pkg/types"
)

/*SerializableData struct exists purely for serialaization purposes*/
type SerializableData struct {
	ContactIdentities []types.Identity `json:"contact_identities"`
	Rooms             []*types.Room    `json:"rooms"`
}

const (
	socksPort   = 10048
	controlPort = 10049
	loContPort  = 10050
	loConvPort  = 10051
	apiPort     = 10052

	tordir         = "tordir"
	blobdir        = "onionblobs"
	datafile       = "onionmsg.zstd"
	unixSocketName = "onionmsg.sock"
)

var (
	interactive bool
	unixSocket  bool

	loadFuse bool

	data = SerializableData{}

	torInstance *tor.Instance
	//APISocket is the socket that the API for frontend is served on
	APISocket net.Listener

	//LastCommit is the first 7 letters of the last commit, injected at build time
	LastCommit = "unknown"
	//BuildVer is the Go Version used to build this programm, obviously injected at build time
	BuildVer = "unknown"
)

//StartDaemon is used to start the application for creating identites and rooms.
//Also sending/receiving messages etc.
//Basically everything except the frontend API.
func StartDaemon(interactiveArg, unixSocketArg bool) {
	var err error

	interactive = interactiveArg
	unixSocket = unixSocketArg

	defer func() {
		if err := recover(); err != nil {
			log.Printf("Something went seriously wrong:\n%sTrying to perfrom clean exit", err)
			exitDaemon()
		}
	}()
	startSignalHandler()
	
	if LastCommit != "unknown" || BuildVer != "unknown" {
		log.Printf("Built from #%s with %s\n", LastCommit, BuildVer)
	}

	err = blobmngr.Initialize(blobdir)
	if err != nil {
		log.Panicln(err.Error())
	}

	if unixSocket {
		APISocket, err = sio.CreateUnixSocket(unixSocketName)
	} else {
		APISocket, err = sio.CreateTCPSocket(apiPort)
	}
	if err != nil {
		log.Panicln(err.Error())
	}

	//go startAPIServer()

	torInstance, err = tor.NewInstance(context.Background(), tor.Conf{
		SocksPort:   9050,
		ControlPort: 9051,
		DataDir:     "./tordir",
		TorRC:       "./torrc",
	})
	if err != nil {
		log.Panicln(err.Error())
	}

	err = loadData()
	if err != nil && !os.IsNotExist(err) {
		log.Panicln(err.Error())
	}
	loadFuse = true

	err = initContIDServices()
	if err != nil {
		log.Panicln(err.Error())
	}
	err = initRooms()
	if err != nil {
		log.Panicln(err.Error())
	}

	go sio.StartLocalServer(loContPort, contClientHandler)
	go sio.StartLocalServer(loConvPort, convClientHandler)

	if interactive {
		go startInteractive()
	}
}

func saveData() (err error) {
	err = sio.SaveDataCompressed(datafile, &data)
	return
}

func loadData() (err error) {
	err = sio.LoadCompressedData(datafile, &data)
	return
}

func startSignalHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Printf("Received shutdown signal, exiting gracefully...")
		exitDaemon()
	}()
}

func exitDaemon() {
	if torInstance != nil {
		torInstance.Stop()
	}

	if loadFuse {
		err := saveData()
		if err != nil {
			log.Println(err.Error())
		}
	}

	os.Exit(0)
}
