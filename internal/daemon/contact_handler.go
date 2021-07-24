package daemon

import (
	"log"
	"net"

	"github.com/craumix/onionmsg/pkg/sio"
	"github.com/craumix/onionmsg/pkg/types"
)

func contClientHandler(c net.Conn) {
	dconn := sio.NewDataIO(c)
	defer dconn.Close()

	req := &types.ContactRequest{}
	err := dconn.ReadStruct(req)
	if err != nil {
		log.Println(err.Error())
		return
	}

	cont, ok := GetContactID(req.RemoteFP)
	if !ok {
		log.Printf("Contact id %s unknown\n", req.RemoteFP)
		return
	}

	remoteID, _ := types.NewRemoteIdentity(req.LocalFP)

	convID := types.NewIdentity()

	resp := &types.ContactResponse{
		ConvFP: convID.Fingerprint(),
		Sig:    cont.Sign(append([]byte(convID.Fingerprint()), req.ID[:]...)),
	}

	_, err = dconn.WriteStruct(resp)
	if err != nil {
		log.Println(err.Error())
		return
	}

	dconn.Flush()

	room := &types.Room{
		Self:  convID,
		Peers: []*types.MessagingPeer{types.NewMessagingPeer(remoteID)},
		ID:    req.ID,
	}
	err = registerRoom(room)
	if err != nil {
		log.Println()
	}

	room.RunRemoteMessageQueues(torInstance.Proxy)

	//Kinda breaks interactive
	//log.Printf("Exchange succesfull uuid %s sent id %s", id, convID.Fingerprint())

}