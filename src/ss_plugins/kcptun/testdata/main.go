package main

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/golang/snappy"
	kcp "github.com/metacubex/kcp-go"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
)

const password = "shoes-kcptun-interop"

type compressedConn struct {
	net.Conn
	reader *snappy.Reader
	writer *snappy.Writer
}

func newCompressedConn(conn net.Conn) *compressedConn {
	return &compressedConn{
		Conn:   conn,
		reader: snappy.NewReader(conn),
		writer: snappy.NewBufferedWriter(conn),
	}
}

func (conn *compressedConn) Read(buffer []byte) (int, error) {
	return conn.reader.Read(buffer)
}

func (conn *compressedConn) Write(buffer []byte) (int, error) {
	if _, err := conn.writer.Write(buffer); err != nil {
		return 0, err
	}
	if err := conn.writer.Flush(); err != nil {
		return 0, err
	}
	return len(buffer), nil
}

func main() {
	if len(os.Args) != 3 {
		panic("usage: interop-client HOST:PORT SMUX_VERSION")
	}
	version, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}
	key := pbkdf2.Key([]byte(password), []byte("kcp-go"), 4096, 32, sha1.New)
	block, err := kcp.NewAESBlockCrypt(key[:16])
	if err != nil {
		panic(err)
	}
	conn, err := kcp.DialWithOptions(os.Args[1], block, 4, 2)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	conn.SetStreamMode(true)
	conn.SetWriteDelay(false)
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetWindowSize(256, 512)
	if !conn.SetMtu(1350) {
		panic("failed to set KCP MTU")
	}
	conn.SetACKNoDelay(true)

	muxConfig := smux.DefaultConfig()
	muxConfig.Version = version
	muxConfig.MaxReceiveBuffer = 4 * 1024 * 1024
	muxConfig.MaxStreamBuffer = 1024 * 1024
	muxConfig.MaxFrameSize = 8192
	muxConfig.KeepAliveInterval = time.Second
	muxConfig.KeepAliveTimeout = 3 * time.Second
	session, err := smux.Client(newCompressedConn(conn), muxConfig)
	if err != nil {
		panic(err)
	}
	defer session.Close()
	stream, err := session.OpenStream()
	if err != nil {
		panic(err)
	}
	defer stream.Close()

	payload := make([]byte, 512*1024)
	for index := range payload {
		payload[index] = byte(index*31 + 17)
	}
	writeResult := make(chan error, 1)
	go func() {
		_, err := stream.Write(payload)
		writeResult <- err
	}()
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, echo); err != nil {
		panic(err)
	}
	if err := <-writeResult; err != nil {
		panic(err)
	}
	if !bytes.Equal(payload, echo) {
		panic("echo payload mismatch")
	}
	fmt.Printf("kcp-go AES-128/FEC/Snappy/smux-v%d echo ok (%d bytes)\n", version, len(payload))
}
