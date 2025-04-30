package ioconn_test

import (
	"io"
	"testing"

	"github.com/tg123/sshpiper/libplugin/ioconn"
)

func TestDial(t *testing.T) {
	in, out := io.Pipe()

	conn, err := ioconn.Dial(in, out)
	if err != nil {
		t.Errorf("Dial returned an error: %v", err)
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			t.Errorf("failed to close conn: %v", cerr)
		}
	}()

	go func() {

		_, _ = conn.Write([]byte("hello"))
	}()
	buf := make([]byte, 5)
	_, _ = conn.Read(buf)

	if string(buf) != "hello" {
		t.Errorf("unexpected string read: %v", string(buf))
	}
}
