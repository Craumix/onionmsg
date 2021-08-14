package test

import (
	"context"
	"github.com/craumix/onionmsg/test/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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
)

func setupMessagingPeerTests() {
	connection.GetConnFunc = mocks.GetMockedConnWrapper

	mocks.MockedConn = &mocks.MockConnWrapper{}

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

	mocks.MockedConn.GetMockedConnWrapperError = GetTestError()

	peer.QueueMessage(message)

	assert.Equal(t, 1, len(peer.MQueue), "Message not queued!")
}

func TestQueueMessageSendMessageSuccessful(t *testing.T) {
	setupMessagingPeerTests()

	peer.QueueMessage(message)

	assert.Equal(t, 0, len(peer.MQueue), "Message not sent!")
}

func TestSendMessages(t *testing.T) {
	setupMessagingPeerTests()

	_, err := peer.SendMessages(message)

	assert.NoError(t, err)
	assert.Equal(t, room.ID[:], mocks.MockedConn.WriteBytesInput[0], "Wrong room ID was written to connection!")
	assert.Equal(t, 1, mocks.MockedConn.WriteIntInput[0], "Wrong amount of messages was written to connection!")
	assert.True(t, mocks.MockedConn.FlushCalled, "Connection was not flushed!")
	assert.True(t, mocks.MockedConn.CloseCalled, "Connection was not closed!")
}

func TestSendMessagesNoRoomSet(t *testing.T) {
	setupMessagingPeerTests()

	peer.Room = nil

	sent, err := peer.SendMessages(message)

	assert.Error(t, err, "SendMessages doesn't error when no room is set!")
	assert.Equal(t, 0, sent, "SendMessages doesn't return 0 when no room is set!")
}

func TestRunMessageQueue(t *testing.T) {
	setupMessagingPeerTests()

	peer.QueueMessage(message)
	go peer.RunMessageQueue(room.Ctx, &room)

	time.Sleep(time.Second)

	assert.Equal(t, 0, len(peer.MQueue), "Message not sent!")
}

func TestRunMessageQueueContextCancelled(t *testing.T) {
	setupMessagingPeerTests()

	mocks.MockedConn.GetMockedConnWrapperError = GetTestError()

	timeoutCancel()
	peer.QueueMessage(message)
	peer.RunMessageQueue(timeoutCtx, &room)

	assert.Equal(t, 1, len(peer.MQueue), "Message sent while queue is cancelled!")
}

func TestRunMessageQueueEmpty(t *testing.T) {
	setupMessagingPeerTests()

	peer.RunMessageQueue(timeoutCtx, &room)

	assert.False(t, mocks.MockedConn.GetMockedConnWrapperCalled, "Peer tried to transfer a message!")
}

func TestRunMessageQueueSendMessagesError(t *testing.T) {
	setupMessagingPeerTests()

	mocks.MockedConn.GetMockedConnWrapperError = GetTestError()

	peer.QueueMessage(message)
	peer.RunMessageQueue(timeoutCtx, &room)

	assert.Equal(t, 1, len(peer.MQueue), "Message sent while queue is cancelled!")
}

func TestRunMessageQueueSendMessageSuccessfully(t *testing.T) {
	setupMessagingPeerTests()

	peer.MQueue = append(peer.MQueue, message)

	peer.RunMessageQueue(timeoutCtx, &room)

	assert.Equal(t, 0, len(peer.MQueue), "Message not sent!")
}