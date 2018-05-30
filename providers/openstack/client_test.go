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

package openstack_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/CS-SI/SafeScale/providers"

	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/openstack"
	"github.com/CS-SI/SafeScale/providers/tests"
)

var tester *tests.ClientTester
var client *openstack.Client

func getTester() *tests.ClientTester {
	if tester == nil {

		tester = &tests.ClientTester{
			Service: providers.Service{
				ClientAPI: getClient(),
			},
		}

	}
	return tester

}

func getClient() *openstack.Client {
	if client == nil {
		sf := providers.NewFactory()
		sf.RegisterClient("openstack", &openstack.Client{})
		sf.Load()

		service := sf.Services["TestOpenStack"]
		client = service.ClientAPI.(*openstack.Client)

	}
	return client
}

func Test_Template(t *testing.T) {
	client := getClient()
	//Data structure to apply to userdata.sh template
	type userData struct {
		User        string
		Key         string
		ConfIF      bool
		IsGateway   bool
		AddGateway  bool
		ResolveConf string
		GatewayIP   string
	}
	dataBuffer := bytes.NewBufferString("")
	data := userData{
		User:        api.DefaultUser,
		Key:         "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
		ConfIF:      true,
		IsGateway:   true,
		AddGateway:  true,
		ResolveConf: "dskjfdshjjkdhsksdhhkjs\nsfdsfsdq\ndfsqdfqsdfq",
		GatewayIP:   "172.1.2.1",
	}
	err := client.UserDataTpl.Execute(dataBuffer, data)
	assert.Nil(t, err)
	fmt.Println(dataBuffer.String())
}
func Test_ListImages(t *testing.T) {
	getTester().ListImages(t)
}

func Test_ListVMTemplates(t *testing.T) {
	getTester().ListVMTemplates(t)
}

func Test_CreateKeyPair(t *testing.T) {
	getTester().CreateKeyPair(t)
}

func Test_GetKeyPair(t *testing.T) {
	getTester().GetKeyPair(t)
}

func Test_ListKeyPairs(t *testing.T) {
	getTester().ListKeyPairs(t)
}

func Test_Networks(t *testing.T) {
	getTester().Networks(t)
}

func Test_VMs(t *testing.T) {
	getTester().VMs(t)
}

func Test_StartStopVM(t *testing.T) {
	getTester().StartStopVM(t)
}

func Test_Volume(t *testing.T) {
	getTester().Volume(t)
}

func Test_VolumeAttachment(t *testing.T) {
	getTester().VolumeAttachment(t)
}

func Test_Containers(t *testing.T) {
	getTester().Containers(t)
}

func Test_Objects(t *testing.T) {
	getTester().Objects(t)
}
