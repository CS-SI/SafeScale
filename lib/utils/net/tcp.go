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
	"net"
	"strconv"

	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// CheckRemoteTCP returns true if ip:port is listening, false otherwise
func CheckRemoteTCP(ip string, port int) bool {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 3*temporal.SmallDelay())
	if err != nil {
		return false
	}

	if conn != nil {
		_ = conn.Close()
		return true
	}

	return false
}
