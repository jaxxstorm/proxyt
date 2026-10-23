package cmd

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// interruptSetup handles cancellation even during a blocked request-body read.
// The returned stop function joins an already-running callback before handoff.
func interruptSetup(ctx context.Context, conn net.Conn, client *http.ResponseController) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		_ = conn.SetDeadline(time.Now())
		_ = client.SetReadDeadline(time.Now())
	})
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				<-done
			}
		})
	}
}
