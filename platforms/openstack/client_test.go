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
	"testing"

	"github.com/CS-SI/SafeScale/providers"

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
		service, _ := providers.GetService("TestOpenStack")
		tester = &tests.ClientTester{
			Service: *service,
		}

	}
	return client
}

/* TODO
   review the code to test with userdata.Prepare, or move the test to userdata ?

func Test_Template(t *testing.T) {
	client := getClient()
	//Data structure to apply to userdata.sh template
	type userData struct {
		User       string
		Key        string
		ConfIF     bool
		IsGateway  bool
		AddGateway bool
		ResolvConf string
		GatewayIP  string
	}
	dataBuffer := bytes.NewBufferString("")
	data := userData{
		User:       api.DefaultUser,
		Key:        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
		ConfIF:     true,
		IsGateway:  true,
		AddGateway: true,
		ResolvConf: "dskjfdshjjkdhsksdhhkjs\nsfdsfsdq\ndfsqdfqsdfq",
		GatewayIP:  "172.1.2.1",
	}
	output, err := userdata.Prepare(client, dataBuffer, data)
	assert.Nil(t, err)
	fmt.Println(output.String())
}*/

func Test_ListImages(t *testing.T) {
	getTester().ListImages(t)
}

func Test_ListHostTemplates(t *testing.T) {
	getTester().ListHostTemplates(t)
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

func Test_Hosts(t *testing.T) {
	getTester().Hosts(t)
}

func Test_StartStopHost(t *testing.T) {
	getTester().StartStopHost(t)
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
