/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package huaweicloud_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	providerapi "github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/tests"
)

var tester *tests.ServiceTester
var service iaas.Service
var provider providerapi.Provider

func getTester() (*tests.ServiceTester, error) {
	if tester == nil {
		theService, err := getClient()
		if err != nil {
			return nil, err
		}
		// theService, err := flexibleengine.Build(stacks.AuthenticationOptions{}, stacks.ConfigurationOptions{})
		// if err != nil {
		// 	return nil, err
		// }
		tester = &tests.ServiceTester{
			Service: theService,
		}
	}
	return tester, nil
}

func getClient() (iaas.Service, error) {
	if service == nil {
		tenantName := ""
		if tenantOverride := os.Getenv("TEST_FLEXIBLE"); tenantOverride != "" {
			tenantName = tenantOverride
		}
		var err error
		service, err = iaas.UseService(tenantName)
		if err != nil || service == nil {
			return nil, fmt.Errorf("you must provide a VALID tenant [%v], check your environment variables and your Safescale configuration files", tenantName)
		}
	}
	return service, nil
}

func Test_ListImages(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.ListImages(t)
}

func Test_ListHostTemplates(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.ListHostTemplates(t)
}

func Test_CreateKeyPair(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.CreateKeyPair(t)
}

func Test_GetKeyPair(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.GetKeyPair(t)
}

func Test_ListKeyPairs(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.ListKeyPairs(t)
}

func Test_Networks(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.Networks(t)
}

func Test_Hosts(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.Hosts(t)
}

func Test_StartStopHost(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.StartStopHost(t)
}

func Test_Volume(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.Volume(t)
}

func Test_VolumeAttachment(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.VolumeAttachment(t)
}

func Test_Containers(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.Containers(t)
}

// func Test_Objects(t *testing.T) {
// 	tt, err := getTester()
// 	require.Nil(t, err)
// 	tt.Objects(t)
// }
