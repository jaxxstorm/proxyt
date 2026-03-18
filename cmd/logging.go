package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"

	log "github.com/jaxxstorm/log"
)

func newRuntimeLogger(debug bool) (*log.Logger, error) {
	return buildRuntimeLogger(debug, nil, "")
}

func buildRuntimeLogger(debug bool, output io.Writer, outputPath string) (*log.Logger, error) {
	level := log.InfoLevel
	if debug {
		level = log.DebugLevel
	}

	return log.New(log.Config{
		Level:      level,
		Output:     output,
		OutputPath: outputPath,
	})
}

func closeRuntimeLogger(logger *log.Logger) {
	if logger == nil {
		return
	}

	if err := logger.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to close logger: %v\n", err)
	}
}

func loggedBytes(output *bytes.Buffer) []byte {
	if output == nil {
		return nil
	}

	return output.Bytes()
}
