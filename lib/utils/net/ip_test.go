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
	"math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_IPv4ToUInt32(t *testing.T) {

	var (
		token        []byte
		ip           net.IP
		strip        string
		numberip     uint32
		resultIp     net.IP
		resultUint32 uint32
		resultStr    string
	)

	token = make([]byte, 4)

	for i := 0; i < 20; i++ {

		_, err := rand.Read(token) // nolint
		if err != nil {
			t.FailNow()
		}

		// In
		ip = net.IPv4(token[0], token[1], token[2], token[3])
		strip = fmt.Sprintf("%d.%d.%d.%d", token[0], token[1], token[2], token[3])
		numberip = uint32(token[0])<<24 | uint32(token[1])<<16 | uint32(token[2])<<8 | uint32(token[3])

		// Out and check
		resultUint32 = IPv4ToUInt32(ip)
		require.EqualValues(t, numberip, resultUint32)

		resultUint32 = IPv4StringToUInt32(strip)
		require.EqualValues(t, numberip, resultUint32)

		resultUint32 = IPv4StringToUInt32(strip)
		require.EqualValues(t, numberip, resultUint32)

		resultIp = UInt32ToIPv4(numberip)
		require.EqualValues(t, ip, resultIp)

		resultStr = UInt32ToIPv4String(numberip)
		require.EqualValues(t, strip, resultStr)

	}

}
