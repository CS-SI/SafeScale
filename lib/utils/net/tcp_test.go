//go:build disabled
// +build disabled

/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_CheckRemoteTCP(t *testing.T) {
	// FIXME: We MUST run something in localhost 8888 1st
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
