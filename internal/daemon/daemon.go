package daemon

import (
	"log"
	"net"
	"os"

	"github.com/Craumix/tormsg/internal/sio"
	"github.com/Craumix/tormsg/internal/tor"
	"github.com/Craumix/tormsg/internal/types"
	"github.com/google/uuid"
)

/*SerializableData struct exists purely for serialaization purposes*/
type SerializableData struct {
	ContactIdentities	map[string]*types.Identity	`json:"contact_identities"`
	Rooms				map[uuid.UUID]*types.Room	`json:"rooms"`
}

const (
	socksPort 			= 10048
	controlPort 		= 10049
	contactPort 		= 10050
	conversationPort 	= 10051
	apiPort 			= 10052

	tordir 				= "tordir"
	datafile 			= "tormsg.zstd.aes"
	unixSocketName 		= "tormsg.sock"

	loopback			= "127.0.0.1"
)

var (
	internalTor	bool
	interactive	bool
	unixSocket	bool

	data = SerializableData{
		ContactIdentities: 	make(map[string]*types.Identity),
		Rooms: 				make(map[uuid.UUID]*types.Room),
	}

	torInstance	*tor.TorInstance

	apiSocket	net.Listener
)

func StartDaemon(interactiveArg, internalTorArg, unixSocketArg bool) {
	var err error

	internalTor = internalTorArg
	interactive = interactiveArg
	unixSocket 	= unixSocketArg

	if(unixSocket) {
		apiSocket, err = sio.CreateUnixSocket(unixSocketName)
	}else {
		apiSocket, err = sio.CreateTCPSocket(apiPort)
	}
	if err != nil {
		log.Fatalf(err.Error())
	}

	go startAPIServer()

	torInstance, err = tor.NewTorInstance(internalTor, tordir, socksPort, controlPort)
	if err != nil {
		log.Fatalf(err.Error())
	}

	err = loadData()
	if err != nil && !os.IsNotExist(err) {
		log.Fatalf(err.Error())
	}

	err = loadContactIdentites()
	if err != nil {
		log.Fatalf(err.Error())
	}
	err = loadRooms()
	if err != nil {
		log.Fatalf(err.Error())
	}

	go startContactServer()
	go startRoomServer()

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

func exitDaemon() {
	torInstance.Stop()
	saveData()
	os.Exit(0)
}