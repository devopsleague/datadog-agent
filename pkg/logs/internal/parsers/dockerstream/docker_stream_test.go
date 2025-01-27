// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package dockerstream

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/logs/message"
)

var dockerHeader = string([]byte{1, 0, 0, 0, 0, 0, 0, 0}) + "2018-06-14T18:27:03.246999277Z"
var container1Parser = New("container_1")

func TestGetDockerSeverity(t *testing.T) {
	assert.Equal(t, message.StatusInfo, getDockerSeverity([]byte{1}))
	assert.Equal(t, message.StatusError, getDockerSeverity([]byte{2}))
	assert.Equal(t, "", getDockerSeverity([]byte{3}))
}

func TestDockerStandaloneParserShouldSucceedWithValidInput(t *testing.T) {
	validMessage := dockerHeader + " " + "anything"
	parser := New("container_1")
	logMessage := message.Message{
		Content: []byte(validMessage),
	}
	msg, err := parser.Parse(&logMessage)
	assert.Nil(t, err)
	assert.False(t, msg.ParsingExtra.IsPartial)
	assert.Equal(t, "2018-06-14T18:27:03.246999277Z", msg.ParsingExtra.Timestamp)
	assert.Equal(t, message.StatusInfo, msg.Status)
	assert.Equal(t, []byte("anything"), msg.Content)
}

func TestDockerStandaloneParserShouldHandleEmptyMessage(t *testing.T) {
	logMessage := message.Message{
		Content: []byte(dockerHeader),
	}
	msg, err := container1Parser.Parse(&logMessage)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(msg.Content))
}

func TestDockerStandaloneParserShouldHandleNewlineOnlyMessage(t *testing.T) {
	emptyContent := [3]string{"\\n", "\\r", "\\r\\n"}

	for _, em := range emptyContent {
		logMessage := message.Message{
			Content: []byte("2018-06-14T18:27:03.246999277Z " + em),
		}
		msg, err := container1Parser.Parse(&logMessage)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(msg.Content))
	}
}

func TestDockerStandaloneParserShouldHandleTtyMessage(t *testing.T) {
	logMessage := message.Message{
		Content: []byte("2018-06-14T18:27:03.246999277Z foo"),
	}
	msg, err := container1Parser.Parse(&logMessage)
	assert.Nil(t, err)
	assert.False(t, msg.ParsingExtra.IsPartial)
	assert.Equal(t, "2018-06-14T18:27:03.246999277Z", msg.ParsingExtra.Timestamp)
	assert.Equal(t, message.StatusInfo, msg.Status)
	assert.Equal(t, []byte("foo"), msg.Content)
}

func TestDockerStandaloneParserShouldHandleEmptyTtyMessage(t *testing.T) {
	logMessage := message.Message{
		Content: []byte("2018-06-14T18:27:03.246999277Z"),
	}
	msg, err := container1Parser.Parse(&logMessage)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(msg.Content))
	logMessage.Content = []byte("2018-06-14T18:27:03.246999277Z ")
	msg, err = container1Parser.Parse(&logMessage)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(msg.Content))
}

func TestDockerStandaloneParserShouldFailWithInvalidInput(t *testing.T) {
	var msg []byte
	var err error

	// missing dockerHeader separator
	msg = []byte{}
	msg = append(msg, []byte{1, 0, 0, 0, 0}...)
	logMessage := message.Message{
		Content: msg,
	}
	_, err = container1Parser.Parse(&logMessage)
	assert.Equal(t, errors.New("cannot parse docker message for container container_1: expected a 8 bytes header"), err)

}

func TestDockerStandaloneParserShouldRemovePartialHeaders(t *testing.T) {
	var msgToClean []byte
	var expectedMsg []byte

	// 16kb log
	msgToClean = []byte(buildPartialMessage('a', dockerBufferSize) + dockerHeader)
	expectedMsg = []byte(buildMessage('a', dockerBufferSize))
	logMessage := message.Message{
		Content: msgToClean,
	}
	msg, err := container1Parser.Parse(&logMessage)
	assert.Nil(t, err)
	assert.False(t, msg.ParsingExtra.IsPartial)
	assert.Equal(t, "2018-06-14T18:27:03.246999277Z", msg.ParsingExtra.Timestamp)
	assert.Equal(t, message.StatusInfo, msg.Status)
	assert.Equal(t, expectedMsg, msg.Content)
	assert.Equal(t, dockerBufferSize, len(msg.Content))

	// over 16kb
	logMessage.Content = []byte(buildPartialMessage('a', dockerBufferSize) + buildPartialMessage('b', 50))
	expectedMsg = []byte(buildMessage('a', dockerBufferSize) + buildMessage('b', 50))
	msg, err = container1Parser.Parse(&logMessage)
	assert.Nil(t, err)
	assert.False(t, msg.ParsingExtra.IsPartial)
	assert.Equal(t, "2018-06-14T18:27:03.246999277Z", msg.ParsingExtra.Timestamp)
	assert.Equal(t, message.StatusInfo, msg.Status)
	assert.Equal(t, expectedMsg, msg.Content)
	assert.Equal(t, dockerBufferSize+50, len(msg.Content))

	// three times over 16kb
	logMessage.Content = []byte(buildPartialMessage('a', dockerBufferSize) + buildPartialMessage('a', dockerBufferSize) + buildPartialMessage('a', dockerBufferSize) + buildPartialMessage('b', 50))
	expectedMsg = []byte(buildMessage('a', 3*dockerBufferSize) + buildMessage('b', 50))
	msg, err = container1Parser.Parse(&logMessage)
	assert.Nil(t, err)
	assert.False(t, msg.ParsingExtra.IsPartial)
	assert.Equal(t, "2018-06-14T18:27:03.246999277Z", msg.ParsingExtra.Timestamp)
	assert.Equal(t, message.StatusInfo, msg.Status)
	assert.Equal(t, expectedMsg, msg.Content)
	assert.Equal(t, 3*dockerBufferSize+50, len(msg.Content))
}

func buildPartialMessage(r rune, count int) string {
	return dockerHeader + " " + strings.Repeat(string(r), count)
}

func buildMessage(r rune, count int) string {
	return strings.Repeat(string(r), count)
}
