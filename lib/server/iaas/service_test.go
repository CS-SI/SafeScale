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

package iaas_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	//"github.com/CS-SI/SafeScale/lib/server/iaas/providers/aws"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers/cloudferro"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers/cloudwatt"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers/flexibleengine"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers/opentelekom"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers/ovh"
)

func TestCompare(t *testing.T) {
	s1 := iaas.SimilarityScore("16.04", "ubuntu-xenial-16.04-amd64-server-20170329")
	fmt.Println(s1)
}

func TestParameters(t *testing.T) {
	p := make(map[string]interface{})
	p["String"] = "fkldkjfkdl"
	s := p["String"].(string)
	fmt.Println(s)
	s, _ = p["String2"].(string)
	fmt.Println(s)
}

func TestGetService(t *testing.T) {
	//	provider.Register("aws", &aws.Client{})
	iaas.Register("ovh", ovh.New())
	iaas.Register("cloudferro", cloudferro.New())
	iaas.Register("cloudwatt", cloudwatt.New())
	iaas.Register("flexibleEngine", flexibleengine.New())
	iaas.Register("opentelekom", opentelekom.New())
	ovh, err := iaas.UseService("TestOvh")
	require.Nil(t, err)
	_, err = iaas.UseService("TestCloudferro")
	require.Nil(t, err)
	// _, err := iaas.UseService("TestAws")
	// require.Nil(t, err)
	_, err = iaas.UseService("TestCloudwatt")
	require.Nil(t, err)
	_, err = iaas.UseService("TestFlexibleEngine")
	require.Nil(t, err)
	_, err = iaas.UseService("TestOpenTelekom")
	require.Nil(t, err)
	imgs, err := ovh.ListImages(true)
	require.Nil(t, err)
	require.True(t, len(imgs) > 3)
	//_, err = providers.GetService("TestCloudwatt")
	//require.Nil(t, err)
}
func TestGetServiceErr(t *testing.T) {
	createTenantFile()
	defer deleteTenantFile()
	iaas.Register("ovh", ovh.New())
	iaas.Register("cloudwatt", cloudwatt.New())
	_, err := iaas.UseService("TestOhvehache")
	require.Error(t, err)
	_, err = iaas.UseService("UnknownService")
	require.Error(t, err)
}
