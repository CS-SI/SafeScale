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
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/utils"
)

func TestTenants(t *testing.T) {
	createTenantFile()
	defer deleteTenantFile()

	tenants, err := iaas.GetTenants()
	require.NoError(t, err)

	foundOhVeHache := false
	foundCloudWhat := false
	for tenant, client := range tenants {
		fmt.Printf("Tenant: '%s'\tClient: '%s'\n", tenant, client)
		if tenant == "TestOhvehache" {
			foundOhVeHache = true
		}
		if tenant == "TestCloudWhat" {
			foundCloudWhat = true
		}
	}
	require.True(t, foundOhVeHache)
	require.True(t, foundCloudWhat)
}

func TestTenantsWithNoTenantFile(t *testing.T) {
	//ARRANGE
	// "Hide" any existing tenants.toml
	hideTenantFiles()
	defer unhideTenantFiles()

	//ACT
	_, err := iaas.GetTenants()

	//ASSERT
	require.Error(t, err)
}
func TestTenantsWithNoNameTenantFile(t *testing.T) {
	createNoNameTenantFile()
	defer deleteTenantFile()

	_, err := iaas.GetTenants()

	require.Error(t, err)
}
func TestTenantsWithNoClientTenantFile(t *testing.T) {
	createNoClientTenantFile()
	defer deleteTenantFile()

	_, err := iaas.GetTenants()

	require.Error(t, err)
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
func createNoClientTenantFile() {
	filename, err := filepath.Abs(filepath.Join(".", "tenants.toml"))
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		panic(err)
	}

	defer file.Close()

	// write some text line-by-line to file
	_, err = file.WriteString("[[tenants]]\nname = \"TestOhvehache\"\n")
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
func createNoNameTenantFile() {
	filename, err := filepath.Abs(filepath.Join(".", "tenants.toml"))
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		panic(err)
	}

	defer file.Close()

	// write some text line-by-line to file
	_, err = file.WriteString("[[tenants]]\nclient = \"hovehache\"\n")
	if err != nil {
		return
	}
	_, err = file.WriteString("[[tenants]]\nclient = \"cloudwhat\"\n")
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

func hideTenantFiles() {
	configPathes := []string{".", "$HOME/.safescale", "$HOME/.config/safescale", "/etc/safescale"}
	for _, p := range configPathes {
		tenantFile := path.Join(utils.AbsPathify(p), "tenants.toml")
		bakcupName := path.Join(utils.AbsPathify(p), "bak_tenants.toml")
		if _, err := os.Stat(tenantFile); err == nil {
			os.Rename(tenantFile, bakcupName)
		}
	}
}
func unhideTenantFiles() {
	configPathes := []string{".", "$HOME/.safescale", "$HOME/.config/safescale", "/etc/safescale"}
	for _, p := range configPathes {
		tenantFile := path.Join(utils.AbsPathify(p), "tenants.toml")
		bakcupName := path.Join(utils.AbsPathify(p), "bak_tenants.toml")
		if _, err := os.Stat(bakcupName); err == nil {
			os.Rename(bakcupName, tenantFile)
		}
	}
}
