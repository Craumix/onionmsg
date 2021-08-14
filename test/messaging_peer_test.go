package test

import (
	"context"
	"fmt"
	"github.com/craumix/onionmsg/test/mocks"
	"github.com/google/uuid"
	"testing"
	"time"

	"github.com/craumix/onionmsg/pkg/sio/connection"
	"github.com/craumix/onionmsg/pkg/types"
)

var (
	peer    *types.MessagingPeer
	message types.Message
	room    types.Room

	timeoutCtx    context.Context
	timeoutCancel context.CancelFunc

	testError error
)

func setupMessagingPeerTests() {
	connection.GetConnFunc = mocks.GetMockedConnWrapper

	mocks.MockedConn = &mocks.MockConnWrapper{}

	testError = fmt.Errorf("test error")

	identity, _ := types.NewRemoteIdentity("Test")
	peer = types.NewMessagingPeer(identity)

	message = types.Message{
		Meta: types.MessageMeta{
			Sender:      "test",
			Time:        time.Time{},
			Type:        "mtype.text",
			ContentInfo: types.MessageContentInfo{},
		},
		Content: []byte("this is a test"),
	}

	room = types.Room{
		Self:     types.NewIdentity(),
		Peers:    nil,
		ID:       uuid.New(),
		Name:     "",
		Messages: nil,
	}

	room.SetContext(context.TODO())

	peer.Room = &room

	timeoutCtx, timeoutCancel = context.WithTimeout(room.Ctx, time.Second*4)
}

func TestQueueMessageSendMessagesError(t *testing.T) {
	setupMessagingPeerTests()

	mocks.MockedConn.GetMockedConnWrapperError = testError

	peer.QueueMessage(message)

	if len(peer.MQueue) != 1 {
		t.Error("Message not queued!")
	}
}

func TestQueueMessageSendMessageSuccessful(t *testing.T) {
	setupMessagingPeerTests()

	peer.QueueMessage(message)

	if len(peer.MQueue) != 0 {
		t.Error("Message not sent!")
	}
}

func TestSendMessages(t *testing.T) {
	setupMessagingPeerTests()

	_, err := peer.SendMessages(message)

	if err != nil {
		t.Error(err)
	}

	if !SameByteArray(mocks.MockedConn.WriteBytesInput[0], room.ID[:]) {
		t.Error("Wrong room ID was written to connection!")
	}

	if mocks.MockedConn.WriteIntInput[0] != 1 {
		t.Error("Wrong amount of messages was written to connection!")
	}

	if !mocks.MockedConn.FlushCalled {
		t.Error("Connection was not flushed!")
	}

	if !mocks.MockedConn.CloseCalled {
		t.Error("Connection was not closed!")
	}
}

func TestSendMessagesNoRoomSet(t *testing.T) {
	setupMessagingPeerTests()

	peer.Room = nil

	sent, err := peer.SendMessages(message)

	if err == nil {
		t.Error("SendMessages doesn't error when no room is set!")
	}

	if sent != 0 {
		t.Error("SendMessages doesn't return 0 when no room is set!")
	}
}

func TestRunMessageQueue(t *testing.T) {
	setupMessagingPeerTests()

	peer.QueueMessage(message)
	go peer.RunMessageQueue(room.Ctx, &room)

	time.Sleep(time.Second)

	if len(peer.MQueue) != 0 {
		t.Error("Message was not sent!")
	}
}

func TestRunMessageQueueContextCancelled(t *testing.T) {
	setupMessagingPeerTests()

	mocks.MockedConn.GetMockedConnWrapperError = testError

	timeoutCancel()
	peer.QueueMessage(message)
	peer.RunMessageQueue(timeoutCtx, &room)

	if len(peer.MQueue) != 1 {
		t.Error("Message sent while queue is cancelled!")
	}
}

func TestRunMessageQueueEmpty(t *testing.T) {
	setupMessagingPeerTests()

	peer.RunMessageQueue(timeoutCtx, &room)

	if mocks.MockedConn.GetMockedConnWrapperCalled {
		t.Error("Peer tried to transfer a message!")
	}
}

func TestRunMessageQueueSendMessagesError(t *testing.T) {
	setupMessagingPeerTests()

	mocks.MockedConn.GetMockedConnWrapperError = testError

	peer.QueueMessage(message)
	peer.RunMessageQueue(timeoutCtx, &room)

	if len(peer.MQueue) != 1 {
		t.Error("Message transferred while queue is cancelled!")
	}
}

func TestRunMessageQueueSendMessageSuccessfully(t *testing.T) {
	setupMessagingPeerTests()

	peer.MQueue = append(peer.MQueue, message)

	peer.RunMessageQueue(timeoutCtx, &room)

	if len(peer.MQueue) != 0 {
		t.Error("Message was not sent!")
	}

}
