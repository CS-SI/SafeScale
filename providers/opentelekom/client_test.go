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

package opentelekom_test

import (
	"errors"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/opentelekom"

	"github.com/CS-SI/SafeScale/providers/tests"
)

var tester *tests.ClientTester
var client *opentelekom.Client

func getTester() (*tests.ClientTester, error) {
	if tester == nil {
		the_client, err := getClient()

		if err != nil {
			return nil, err
		}

		tester = &tests.ClientTester{
			Service: providers.Service{
				ClientAPI: the_client,
			},
		}

	}
	return tester, nil
}

func getClient() (*opentelekom.Client, error) {
	if client == nil {
		service, err := providers.GetService("TestOpenTelekom")
		if err != nil {
			return nil, errors.New("You must provide a VALID tenant name in the environment variable TENANT_NAME_TEST, check your environment variables and your Safescale configuration files")
		}
		client = service.ClientAPI.(*opentelekom.Client)
	}
	return client, nil
}

func Test_ListImages(t *testing.T) {
	tt, err := getTester()
	require.Nil(t, err)
	tt.ListImages(t)
}

func Test_ListHostTemplates(t *testing.T) {
	tt, err := getTester()
	require.Nil(t, err)
	tt.ListHostTemplates(t)
}

func Test_CreateKeyPair(t *testing.T) {
	tt, err := getTester()
	require.Nil(t, err)
	tt.CreateKeyPair(t)
}

func Test_GetKeyPair(t *testing.T) {
	tt, err := getTester()
	require.Nil(t, err)
	tt.GetKeyPair(t)
}

func Test_ListKeyPairs(t *testing.T) {
	tt, err := getTester()
	require.Nil(t, err)
	tt.ListKeyPairs(t)
}

func Test_Networks(t *testing.T) {
	tt, err := getTester()
	require.Nil(t, err)
	tt.Networks(t)
}

func Test_Hosts(t *testing.T) {
	tt, err := getTester()
	require.Nil(t, err)
	tt.Hosts(t)
}

func Test_StartStopHost(t *testing.T) {
	tt, err := getTester()
	require.Nil(t, err)
	tt.StartStopHost(t)
}

func Test_Volume(t *testing.T) {
	tt, err := getTester()
	require.Nil(t, err)
	tt.Volume(t)
}

func Test_VolumeAttachment(t *testing.T) {
	tt, err := getTester()
	require.Nil(t, err)
	tt.VolumeAttachment(t)
}

func Test_Containers(t *testing.T) {
	tt, err := getTester()
	require.Nil(t, err)
	tt.Containers(t)
}

func Test_Objects(t *testing.T) {
	tt, err := getTester()
	require.Nil(t, err)
	tt.Objects(t)
}
