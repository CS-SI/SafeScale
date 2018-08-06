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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/CS-SI/SafeScale/providers"

	"github.com/CS-SI/SafeScale/providers/tests"
)

var tester *tests.ClientTester

func getClient() *tests.ClientTester {
	if tester == nil {
		service, _ := providers.GetService("TestOvh")
		tester = &tests.ClientTester{
			Service: *service,
		}
	}
	return tester

}

func Test_GetTemplate(t *testing.T) {
	tpls, err := getClient().Service.ListTemplates()
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
	getClient().ListImages(t)
}

func Test_ListHostTemplates(t *testing.T) {
	getClient().ListHostTemplates(t)
	tpls, err := getClient().Service.ListTemplates()
	assert.Nil(t, err)
	assert.NotEmpty(t, tpls)
	for _, f := range tpls {
		assert.True(t, !strings.HasPrefix(strings.ToLower(f.Name), "win"))
		assert.True(t, !strings.HasSuffix(strings.ToLower(f.Name), "flex"))
	}
}

func Test_CreateKeyPair(t *testing.T) {
	getClient().CreateKeyPair(t)
}

func Test_GetKeyPair(t *testing.T) {
	getClient().GetKeyPair(t)
}

func Test_ListKeyPairs(t *testing.T) {
	getClient().ListKeyPairs(t)
}

func Test_Networks(t *testing.T) {
	getClient().Networks(t)
}

func Test_Hosts(t *testing.T) {
	getClient().Hosts(t)
}

func Test_StartStopHost(t *testing.T) {
	getClient().StartStopHost(t)
}

func Test_Volume(t *testing.T) {
	getClient().Volume(t)
}

func Test_VolumeAttachment(t *testing.T) {
	getClient().VolumeAttachment(t)
}

func Test_Containers(t *testing.T) {
	getClient().Containers(t)
}

func Test_Objects(t *testing.T) {
	getClient().Objects(t)
}
