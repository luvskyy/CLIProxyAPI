package clickhouse

import (
	"bufio"
	"io"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/bodycapture"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/httpwire"
)

// teeReadCloser copies request body bytes into the capture as they are read.
type teeReadCloser struct {
	body    io.ReadCloser
	capture *bodycapture.Capture
}

func (t *teeReadCloser) Read(p []byte) (int, error) {
	n, err := t.body.Read(p)
	if n > 0 {
		t.capture.WriteRequest(p[:n])
	}
	return n, err
}

func (t *teeReadCloser) Close() error {
	return t.body.Close()
}

// captureWriter copies response body bytes into the capture after they are
// written to the client.
type captureWriter struct {
	gin.ResponseWriter
	capture  *bodycapture.Capture
	hijacked bool
}

func (w *captureWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	if n > 0 {
		w.capture.WriteResponse(data[:n])
	}
	return n, err
}

func (w *captureWriter) WriteString(data string) (int, error) {
	n, err := w.ResponseWriter.WriteString(data)
	if n > 0 {
		w.capture.WriteResponse([]byte(data[:n]))
	}
	return n, err
}

func (w *captureWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := w.ResponseWriter.Hijack()
	if err == nil {
		w.hijacked = true
	}
	return conn, rw, err
}

// FlushError forwards transport flush errors to the wrapped writer.
func (w *captureWriter) FlushError() error {
	return httpwire.FlushResponse(w.ResponseWriter)
}

// Unwrap exposes the wrapped writer to http.ResponseController.
func (w *captureWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
