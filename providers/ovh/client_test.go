/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
package ovh_test

import (
	"errors"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/CS-SI/SafeScale/providers"

	"github.com/CS-SI/SafeScale/providers/tests"
)

var tester *tests.ClientTester

func getClient() (*tests.ClientTester, error) {
	if tester == nil {
		service, err := providers.GetService("TestOvh")
		if err != nil {
			return nil, errors.New("You must provide a VALID tenant name in the environment variable TENANT_NAME_TEST, check your environment variables and your Safescale configuration files")
		}
		tester = &tests.ClientTester{
			Service: *service,
		}
	}
	return tester, nil

}

func Test_GetTemplate(t *testing.T) {
	cli, err := getClient()
	require.Nil(t, err)
	tpls, err := cli.Service.ListTemplates(false)
	assert.NoError(t, err)
	find := false
	for _, tpl := range tpls {
		if tpl.Name == "g3-120" {
			assert.Equal(t, 3, tpl.GPUNumber)
			assert.Equal(t, "NVIDIA 1080 TI", tpl.GPUType)
			find = true
		}
	}
	assert.True(t, find)

}

func Test_ListImages(t *testing.T) {
	cli, err := getClient()
	require.Nil(t, err)
	cli.ListImages(t)
}

func Test_ListHostTemplates(t *testing.T) {
	cli, err := getClient()
	require.Nil(t, err)
	cli.ListHostTemplates(t)
	tpls, err := cli.Service.ListTemplates(false)
	assert.Nil(t, err)
	assert.NotEmpty(t, tpls)
	for _, f := range tpls {
		assert.True(t, !strings.HasPrefix(strings.ToLower(f.Name), "win"))
		assert.True(t, !strings.HasSuffix(strings.ToLower(f.Name), "flex"))
	}
}

func Test_CreateKeyPair(t *testing.T) {
	cli, err := getClient()
	require.Nil(t, err)
	cli.CreateKeyPair(t)
}

func Test_GetKeyPair(t *testing.T) {
	cli, err := getClient()
	require.Nil(t, err)
	cli.GetKeyPair(t)
}

func Test_ListKeyPairs(t *testing.T) {
	cli, err := getClient()
	require.Nil(t, err)
	cli.ListKeyPairs(t)
}

func Test_Networks(t *testing.T) {
	cli, err := getClient()
	require.Nil(t, err)
	cli.Networks(t)
}

func Test_Hosts(t *testing.T) {
	cli, err := getClient()
	require.Nil(t, err)
	cli.Hosts(t)
}

func Test_StartStopHost(t *testing.T) {
	cli, err := getClient()
	require.Nil(t, err)
	cli.StartStopHost(t)
}

func Test_Volume(t *testing.T) {
	cli, err := getClient()
	require.Nil(t, err)
	cli.Volume(t)
}

func Test_VolumeAttachment(t *testing.T) {
	cli, err := getClient()
	require.Nil(t, err)
	cli.VolumeAttachment(t)
}

func Test_Containers(t *testing.T) {
	cli, err := getClient()
	require.Nil(t, err)
	cli.Containers(t)
}

func Test_Objects(t *testing.T) {
	cli, err := getClient()
	require.Nil(t, err)
	cli.Objects(t)
}
