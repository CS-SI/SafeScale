/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package sshtunnel

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sanity-io/litter"
)

type keepAliveCfg struct {
	tcpKeepaliveTime   uint
	tcpKeepaliveIntvl  uint
	tcpKeepaliveProbes uint
}

func newKeepAliveCfg(tcpKeepaliveTime uint, tcpKeepaliveIntvl uint, tcpKeepaliveProbes uint) *keepAliveCfg {
	return &keepAliveCfg{tcpKeepaliveTime: tcpKeepaliveTime, tcpKeepaliveIntvl: tcpKeepaliveIntvl, tcpKeepaliveProbes: tcpKeepaliveProbes}
}

func newDefaultKeepAliveCfg() *keepAliveCfg {
	return newKeepAliveCfg(7200, 75, 9)
}

func newKeepAliveCfgFromSystem() *keepAliveCfg { // nolint
	ka := newDefaultKeepAliveCfg()
	ka.readFromCfg()
	return ka
}

func (k keepAliveCfg) String() string {
	litter.Config.HidePrivateFields = false
	return litter.Sdump(k)
}

func (k keepAliveCfg) Dump() string {
	litter.Config.HidePrivateFields = false
	return litter.Sdump(k)
}

func readIntFromFile(name string) (uint, error) {
	content, err := os.ReadFile(name)
	if err != nil {
		return 0, err
	}

	theLines := strings.Split(string(content), "\n")
	if len(theLines) == 0 {
		return 0, fmt.Errorf("error: empty file")
	}
	theIP := strings.TrimSpace(theLines[0])

	theNum, err := strconv.Atoi(theIP)
	return uint(theNum), err
}

func (k *keepAliveCfg) readFromCfg() {
	if num, err := readIntFromFile("/proc/sys/net/ipv4/tcp_keepalive_time"); err == nil {
		k.tcpKeepaliveTime = num
	}
	if num, err := readIntFromFile("/proc/sys/net/ipv4/tcp_keepalive_intvl"); err == nil {
		k.tcpKeepaliveIntvl = num
	}
	if num, err := readIntFromFile("/proc/sys/net/ipv4/tcp_keepalive_probes"); err == nil {
		k.tcpKeepaliveProbes = num
	}
}
