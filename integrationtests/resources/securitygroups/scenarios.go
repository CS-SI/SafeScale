//go:build (integration && securitygrouptests) || allintegration
// +build integration,securitygrouptests allintegration

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

package securitygroups

import (
	"testing"
)

func SecurityGroupLife(t *testing.T) {
	// FIXME: implement this test
}

func AddRuleToExistingSecurityGroup(t *testing.T) {
	// FIXME: implement this test
}

// CheckDefaultSecGroups checks that all ports (except 22) are closed by default
func CheckDefaultSecGroups(t *testing.T) {
	// FIXME: Implement this test
}

// OpenPort unblocks a port in a gateway, runs a server in the gateway, then accesses the server using the port
func OpenPort(t *testing.T) {
	// FIMXE: Implement this test
}

func init() {
}
