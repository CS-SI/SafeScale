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

package ssh

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"

	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
)

func TestNewConnector(t *testing.T) {
	theConf := ssh.NewConfig("", "", 0, "you", "xxx", 0, "", nil, nil)
	got, err := NewConnector(theConf, ConnectorWithLib())
	if err != nil {
		t.Error(err)
	}

	nomo := spew.Sdump(got)
	assert.Contains(t, nomo, "bylib")
}

func TestNewConnectorCli(t *testing.T) {
	theConf := ssh.NewConfig("", "", 0, "you", "xxx", 0, "", nil, nil)
	got, err := NewConnector(theConf, ConnectorWithCli())
	if err != nil {
		t.Error(err)
	}

	nomo := spew.Sdump(got)
	assert.Contains(t, nomo, "bycli")
}
