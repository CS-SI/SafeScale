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

package flexibleengine_test

import (
	"testing"

	"github.com/CS-SI/SafeScale/providers"

	"github.com/CS-SI/SafeScale/providers/flexibleengine"
	"github.com/CS-SI/SafeScale/providers/tests"
)

var tester *tests.ClientTester
var client *flexibleengine.Client

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

func getClient() *flexibleengine.Client {
	if client == nil {
		service, _ := providers.GetService("TestFlexibleEngine")
		client = service.ClientAPI.(*flexibleengine.Client)
	}
	return client
}

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
