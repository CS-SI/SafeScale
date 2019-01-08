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

package iaas_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/iaas/provider"
	//"github.com/CS-SI/SafeScale/iaas/provider/aws"
	"github.com/CS-SI/SafeScale/iaas/provider/cloudferro"
	"github.com/CS-SI/SafeScale/iaas/provider/cloudwatt"
	"github.com/CS-SI/SafeScale/iaas/provider/flexibleengine"
	"github.com/CS-SI/SafeScale/iaas/provider/opentelekom"
	"github.com/CS-SI/SafeScale/iaas/provider/ovh"
)

func TestCompare(t *testing.T) {
	s1 := provider.SimilarityScore("16.04", "ubuntu-xenial-16.04-amd64-server-20170329")
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
	provider.Register("ovh", &ovh.Client{})
	provider.Register("cloudferro", &cloudferro.Client{})
	provider.Register("cloudwatt", &cloudwatt.Client{})
	provider.Register("flexibleEngine", &flexibleengine.Client{})
	provider.Register("opentelekom", &opentelekom.Client{})
	ovh, err := provider.GetService("TestOvh")
	require.Nil(t, err)
	_, err := provider.GetService("TestCloudferro")
	require.Nil(t, err)
	// _, err := provider.GetService("TestAws")
	// require.Nil(t, err)
	_, err = provider.GetService("TestCloudwatt")
	require.Nil(t, err)
	_, err = provider.GetService("TestFlexibleEngine")
	require.Nil(t, err)
	_, err = provider.GetService("TestOpenTelekom")
	require.Nil(t, err)
	imgs, err := ovh.ListImages()
	require.Nil(t, err)
	require.True(t, len(imgs) > 3)
	//_, err = providers.GetService("TestCloudwatt")
	//require.Nil(t, err)
}
func TestGetServiceErr(t *testing.T) {
	createTenantFile()
	defer deleteTenantFile()
	provider.Register("ovh", &ovh.Client{})
	provider.Register("cloudwatt", &cloudwatt.Client{})
	_, err := provider.GetService("TestOhvehache")
	require.Error(t, err)
	_, err = provider.GetService("UnknownService")
	require.Error(t, err)
}
