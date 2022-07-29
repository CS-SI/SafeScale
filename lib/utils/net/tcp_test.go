package net

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_CheckRemoteTCP(t *testing.T) {

	v := CheckRemoteTCP("127.0.0.1", 8888)
	require.False(t, v)

	server, err := net.Listen("tcp", "127.0.0.1:8888")
	if err != nil {
		t.Logf("Fail to open port 8888, %s", err.Error())
		t.SkipNow()
		return
	}
	defer server.Close()

	go func(t *testing.T) {
		for {
			conn, err := server.Accept()
			if err != nil {
				fmt.Println("Error accepting: ", err.Error())
				os.Exit(1)
			}
			t.Log("Detect entering tcp connexion")
			conn.Close()
			break
		}
	}(t)

	v = CheckRemoteTCP("127.0.0.1", 8888)
	require.True(t, v)

}
