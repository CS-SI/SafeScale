/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/tests"
)

func getTester() (*tests.ServiceTester, error) {
	theService, err := getService()
	if err != nil {
		return nil, err
	}
	tester := &tests.ServiceTester{
		Service: theService,
	}

	return tester, nil
}

func getService() (iaas.Service, error) {
	tenantName := ""
	if tenantOverride := os.Getenv("TEST_OVH"); tenantOverride != "" {
		tenantName = tenantOverride
	}

	if tenantName == "" {
		return nil, fmt.Errorf("you must provide a VALID tenant [%v], check your environment variables and your Safescale configuration files", tenantName)
	}

	service, err := iaas.UseService(tenantName, "")
	if err != nil || service == nil {
		return nil, fmt.Errorf("you must provide a VALID tenant [%v], check your environment variables and your Safescale configuration files", tenantName)
	}

	return service, nil
}

// Test that we have templates, and each template has 1 or more cores
func Test_GetTemplates(t *testing.T) {
	ctx := context.Background()
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tpls, err := cli.Service.ListTemplates(ctx, false)
	assert.NoError(t, err)
	assert.True(t, len(tpls) > 0)

	for _, tpl := range tpls {
		fmt.Println(tpl.Cores)
		assert.True(t, tpl.Cores > 0)
	}
}

// Test that we have templates with GPUs
func Test_GetGpuTemplates(t *testing.T) {
	ctx := context.Background()
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tpls, err := cli.Service.ListTemplates(ctx, true)
	assert.NoError(t, err)
	assert.True(t, len(tpls) > 0)

	withGPU := false
	for _, tpl := range tpls {
		if tpl.GPUNumber > 0 {
			withGPU = true
		}
	}

	assert.True(t, withGPU)
}

func TemplateExists(name string) bool {
	ctx := context.Background()
	cli, _ := getTester()
	tpls, _ := cli.Service.ListTemplates(ctx, false)

	find := false
	for _, tpl := range tpls {
		if tpl.Name == name {

			find = true
		}
	}

	return find
}

func Test_GetGpuTemplate(t *testing.T) {
	ctx := context.Background()
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tpls, err := cli.Service.ListTemplates(ctx, false)
	assert.NoError(t, err)
	find := TemplateExists("g3-120")

	if find {
		for _, tpl := range tpls {
			if tpl.Name == "g3-120" {
				fmt.Println(tpl.Cores)
				assert.Equal(t, 3, tpl.GPUNumber)
				assert.Equal(t, "NVIDIA 1080 TI", tpl.GPUType)
				break
			}
		}
	}
}

func Test_Images(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.Images(t)
}

func Test_HostTemplates(t *testing.T) {
	ctx := context.Background()
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.HostTemplates(t)
	tpls, err := cli.Service.ListTemplates(ctx, false)
	assert.Nil(t, err)
	assert.NotEmpty(t, tpls)
	for _, f := range tpls {
		assert.True(t, !strings.HasPrefix(strings.ToLower(f.Name), "win"))
		assert.True(t, !strings.HasSuffix(strings.ToLower(f.Name), "flex"))
	}
}

func Test_KeyPairs(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.KeyPairs(t)
}

func Test_Networks(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.Networks(t)
}

func Test_Hosts(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.Hosts(t)
}

func Test_StartStopHost(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.StartStopHost(t)
}

func Test_Volumes(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.Volumes(t)
}

func Test_Containers(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.Buckets(t)
}
