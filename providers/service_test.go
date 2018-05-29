package providers_test
/*
* Copyright 2015-2018, CS Systemes d'Information, http://www.c-s.fr
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

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/CS-SI/SafeScale/providers/cloudwatt"
	"github.com/CS-SI/SafeScale/providers/flexibleengine"
	"github.com/CS-SI/SafeScale/providers/ovh"

	"github.com/stretchr/testify/assert"

	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/providers"
)

func TestCompare(t *testing.T) {
	s1 := providers.SimilarityScore("16.04", "ubuntu-xenial-16.04-amd64-server-20170329")
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

func TestViper(t *testing.T) {
	createTenantFile()
	defer deleteTenantFile()
	viper.AddConfigPath(".")
	viper.SetConfigName("tenants")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
	fmt.Println(viper.ConfigFileUsed())
	settings := viper.AllSettings()
	tenants, _ := settings["tenants"].([]interface{})
	for _, t := range tenants {
		tenant, _ := t.(map[string]interface{})
		for k, v := range tenant {
			fmt.Println(k, v)
		}
		fmt.Println("--------------------------")
	}
}

func TestGetService(t *testing.T) {
	providers.Register("ovh", &ovh.Client{})
	providers.Register("cloudwatt", &cloudwatt.Client{})
	providers.Register("flexibleEngine", &flexibleengine.Client{})
	ovh, err := providers.GetService("TestOvh")
	assert.NoError(t, err)
	_, err = providers.GetService("TestCloudwatt")
	assert.NoError(t, err)
	_, err = providers.GetService("TestFlexibleEngine")
	assert.NoError(t, err)
	imgs, err := ovh.ListImages()
	assert.NoError(t, err)
	assert.True(t, len(imgs) > 3)
	_, err = providers.GetService("TestCloudwatt")
	assert.NoError(t, err)
}
func TestGetServiceErr(t *testing.T) {
	createTenantFile()
	defer deleteTenantFile()
	providers.Register("ovh", &ovh.Client{})
	providers.Register("cloudwatt", &cloudwatt.Client{})
	_, err := providers.GetService("TestOhvehache")
	assert.Error(t, err)
	_, err = providers.GetService("UnknownService")
	assert.Error(t, err)
}

func TestTenants(t *testing.T) {
	createTenantFile()
	defer deleteTenantFile()

	foundOhVeHache := false
	foundCloudWhat := false
	for tenant, client := range providers.Tenants() {
		fmt.Printf("Tenant: '%s'\tClient: '%s'\n", tenant, client)
		if tenant == "TestOhvehache" {
			foundOhVeHache = true
		}
		if tenant == "TestCloudWhat" {
			foundCloudWhat = true
		}
	}
	assert.True(t, foundOhVeHache)
	assert.True(t, foundCloudWhat)
}

func createTenantFile() {
	filename, err := filepath.Abs(filepath.Join(".", "tenants.toml"))
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		panic(err)
	}

	defer file.Close()

	// write some text line-by-line to file
	_, err = file.WriteString("[[tenants]]\nclient = \"hovehache\"\nname = \"TestOhvehache\"\n")
	if err != nil {
		return
	}
	_, err = file.WriteString("[[tenants]]\nclient = \"cloudwhat\"\nname = \"TestCloudWhat\"\n")
	if err != nil {
		return
	}

	// save changes
	file.Sync()
}

func deleteTenantFile() {
	path, err := filepath.Abs(filepath.Join(".", "tenants.toml"))
	if err != nil {
		fmt.Println(err)
		return
	}
	os.Remove(path)
}
