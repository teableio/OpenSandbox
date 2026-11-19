// Copyright 2026 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	slogger "github.com/alibaba/opensandbox/internal/logger"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_isReservedCloseCode(t *testing.T) {
	for _, code := range []int{websocket.CloseNoStatusReceived, websocket.CloseAbnormalClosure, websocket.CloseTLSHandshake} {
		assert.True(t, isReservedCloseCode(code), "code %d", code)
	}
	for _, code := range []int{websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.ClosePolicyViolation, 4001} {
		assert.False(t, isReservedCloseCode(code), "code %d", code)
	}
}

// closeRelayHarness wires a client to a backend through the ingress proxy and
// reports how the backend saw the connection end.
type closeRelayHarness struct {
	client     *websocket.Conn
	backendEnd chan error
}

func newCloseRelayHarness(t *testing.T) *closeRelayHarness {
	t.Helper()
	Logger = slogger.MustNew(slogger.Config{Level: "debug"})

	backendEnd := make(chan error, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := defaultUpgrader.Upgrade(w, r, nil)
		if err != nil {
			backendEnd <- err
			return
		}
		defer conn.Close()
		for {
			messageType, p, err := conn.ReadMessage()
			if err != nil {
				backendEnd <- err
				return
			}
			if err = conn.WriteMessage(messageType, p); err != nil {
				backendEnd <- err
				return
			}
		}
	}))
	t.Cleanup(backend.Close)
	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	provider := &mockProvider{endpoints: map[string]string{"test-sandbox": backendURL.Hostname()}}
	front := httptest.NewServer(NewProxy(context.Background(), provider, ModeHeader, nil, nil))
	t.Cleanup(front.Close)

	h := http.Header{}
	h.Set(SandboxIngress, "test-sandbox-"+backendURL.Port())
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(front.URL, "http")+"/ws", h)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// Round-trip one message so both legs are known to be established.
	require.NoError(t, client.WriteMessage(websocket.TextMessage, []byte("ping")))
	_, p, err := client.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, "ping", string(p))

	return &closeRelayHarness{client: client, backendEnd: backendEnd}
}

func (h *closeRelayHarness) backendCloseError(t *testing.T) *websocket.CloseError {
	t.Helper()
	select {
	case err := <-h.backendEnd:
		var closeErr *websocket.CloseError
		require.True(t, errors.As(err, &closeErr), "backend should see a Close frame, got: %v", err)
		return closeErr
	case <-time.After(5 * time.Second):
		t.Fatal("backend did not observe the connection ending")
		return nil
	}
}

// A client that disappears without a Close frame must not make the proxy send
// the reserved 1006 status to the backend. A backend that received 1006 on
// the wire would report a protocol error (1002) here instead of a clean close.
func Test_WebSocketProxy_ClientGoneWithoutCloseFrame(t *testing.T) {
	h := newCloseRelayHarness(t)

	// Conn.Close drops the TCP connection without sending a Close frame.
	require.NoError(t, h.client.Close())

	closeErr := h.backendCloseError(t)
	assert.Equal(t, websocket.CloseNormalClosure, closeErr.Code, "close text: %s", closeErr.Text)
}

// Application close codes still reach the backend unchanged.
func Test_WebSocketProxy_RelaysApplicationCloseCode(t *testing.T) {
	h := newCloseRelayHarness(t)

	msg := websocket.FormatCloseMessage(4001, "app says bye")
	require.NoError(t, h.client.WriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second)))

	closeErr := h.backendCloseError(t)
	assert.Equal(t, 4001, closeErr.Code)
	assert.Equal(t, "app says bye", closeErr.Text)
}
