package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestRuntimeSignalProcess(t *testing.T) {
	if os.Getenv("PROXYT_SIGNAL_TEST_CHILD") == "1" {
		withProxyTestGlobals(t)
		events := os.NewFile(3, "events")
		defer events.Close()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		_, selectedPort, _ := net.SplitHostPort(address)
		listener.Close()
		settings, _ = newTestSettings(t)
		for key, value := range map[string]any{"domain": "proxy.example.com", "http-only": true, "bind": "127.0.0.1", "port": selectedPort, "shutdown-delay": "400ms", "shutdown-timeout": "150ms", "upstream-connect-timeout": "1h"} {
			settings.Set(key, value)
		}
		// Both dependency probes and tunnel establishment are hermetic while
		// exercising the real runProxy listener, signals, and shutdown wiring.
		http.DefaultTransport = readyTransport()
		echo := echoDial(t)
		var calls atomic.Int32
		dialControlPlane = func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
			if calls.Add(1) == 1 {
				return echo(ctx, network, addr, config)
			}
			fmt.Fprintln(events, "SETUP")
			<-ctx.Done()
			fmt.Fprintln(events, "CANCELED")
			return nil, ctx.Err()
		}
		fmt.Fprintln(events, address)
		runProxy()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeSignalProcess$")
	command.Env = append(os.Environ(), "PROXYT_SIGNAL_TEST_CHILD=1")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	command.ExtraFiles = []*os.File{writer}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	writer.Close()
	processDone := make(chan struct{})
	var processErr error
	go func() { processErr = command.Wait(); close(processDone) }()
	t.Cleanup(func() { command.Process.Kill(); await(t, processDone) })
	events := make(chan string, 8)
	go func() {
		defer close(events)
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			events <- scanner.Text()
		}
	}()
	nextEvent := func() string {
		t.Helper()
		select {
		case event := <-events:
			return event
		case <-ctx.Done():
			t.Fatal("child event timeout")
			return ""
		}
	}
	address := nextEvent()
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	url := "http://" + address
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get(url + "/health")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	conn, r := openTunnel(t, address)
	exchange(t, conn, r)
	status(t, client, url+"/ready", 200)
	pending, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	io.WriteString(pending, "POST /ts2021 HTTP/1.1\r\nHost: proxy.example.com\r\nContent-Length: 0\r\n\r\n")
	if event := nextEvent(); event != "SETUP" {
		t.Fatalf("event = %q", event)
	}
	start := time.Now()
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	for {
		resp, err := client.Get(url + "/ready")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 503 {
			break
		}
		if time.Since(start) > time.Second {
			t.Fatal("readiness did not withdraw")
		}
		time.Sleep(time.Millisecond)
	}
	status(t, client, url+"/key", 503)
	status(t, client, url+"/health", 200)
	exchange(t, conn, r)
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if event := nextEvent(); event != "CANCELED" {
		t.Fatalf("event = %q", event)
	}
	await(t, processDone)
	if processErr != nil {
		t.Fatalf("child: %v\n%s", processErr, output.String())
	}
	// Race-instrumented child processes add a one-second exit delay.
	if elapsed := time.Since(start); elapsed < 400*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("shutdown duration = %v", elapsed)
	}
	if _, err := r.ReadByte(); err == nil {
		t.Fatal("active tunnel survived process shutdown")
	}
	for _, message := range []string{"Replica draining", "Replica stopped", "deadline", "forced_work"} {
		if !strings.Contains(output.String(), message) {
			t.Fatalf("missing lifecycle log %q in %s", message, output.String())
		}
	}
}
