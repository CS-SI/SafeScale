//go:build ignore
// +build ignore

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

package handlers

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func runOnlyInIntegrationTest(t *testing.T, key string) bool {
	if t == nil {
		return false
	}
	if tenantOverride := os.Getenv(key); tenantOverride == "" {
		t.Skipf("This only runs as an integration test")
		return false
	}
	return true
}

func TestCmds(t *testing.T) {
	runOnlyInIntegrationTest(t, "TEST_SCANNER")

	out, err := exec.Command("bash", "-c", "lscpu -p'CPU,CORE,SOCKET,MAXMHZ,MINMHZ' | tail -1").Output()
	assert.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(out)), ",")
	fmt.Println(len(lines))

	nbThread, err := strconv.Atoi(lines[0])
	nbThread++
	assert.NoError(t, err)
	assert.Equal(t, 8, nbThread)

	nbCore, err := strconv.Atoi(lines[1])
	nbCore++
	assert.NoError(t, err)
	assert.Equal(t, 4, nbCore)

	nbSocket, err := strconv.Atoi(lines[2])
	nbSocket++
	assert.NoError(t, err)
	assert.Equal(t, 1, nbSocket)

	fMax, err := strconv.ParseFloat(lines[3], 64)
	assert.NoError(t, err)
	assert.Equal(t, 3600.0000, fMax)

	fMin, err := strconv.ParseFloat(lines[4], 64)
	assert.NoError(t, err)
	assert.Equal(t, 800.0000, fMin)
}

func TestMain(m *testing.M) {
	if runOnlyInIntegrationTest(nil, "TEST_SCANNER") {
		RunScanner("")
	}
}
