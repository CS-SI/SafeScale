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

package ovh_test

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/tests"
)

var (
	tester  *tests.ServiceTester
	service *iaas.Service
)

func getTester() (*tests.ServiceTester, error) {
	if tester == nil {
		the_service, err := getService()
		if err != nil {
			tester = nil
			the_service = nil
			return nil, err
		}
		tester = &tests.ServiceTester{
			Service: the_service,
		}

	}
	return tester, nil
}

func getService() (*iaas.Service, error) {
	if service == nil {
		tenant_name := ""
		if tenant_override := os.Getenv("TEST_OVH"); tenant_override != "" {
			tenant_name = tenant_override
		}
		var err error
		service, err = iaas.UseService(tenant_name)
		if err != nil || service == nil {
			return nil, errors.New(fmt.Sprintf("You must provide a VALID tenant [%v], check your environment variables and your Safescale configuration files", tenant_name))
		}
	}
	return service, nil
}

// Test that we have templates, and each template has 1 or more cores
func Test_GetTemplates(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tpls, err := cli.Service.ListTemplates(false)
	assert.NoError(t, err)
	assert.True(t, len(tpls) > 0)

	for _, tpl := range tpls {
		fmt.Println(tpl.Cores)
		assert.True(t, tpl.Cores > 0)
	}
}

// Test that we have templates with GPUs
func Test_GetGpuTemplates(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tpls, err := cli.Service.ListTemplates(true)
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
	cli, _ := getTester()
	tpls, _ := cli.Service.ListTemplates(false)

	find := false
	for _, tpl := range tpls {
		if tpl.Name == name {

			find = true
		}
	}

	return find
}

func Test_GetGpuTemplate(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tpls, err := cli.Service.ListTemplates(false)
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

func Test_ListImages(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.ListImages(t)
}

func Test_ListHostTemplates(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.ListHostTemplates(t)
	tpls, err := cli.Service.ListTemplates(false)
	assert.Nil(t, err)
	assert.NotEmpty(t, tpls)
	for _, f := range tpls {
		assert.True(t, !strings.HasPrefix(strings.ToLower(f.Name), "win"))
		assert.True(t, !strings.HasSuffix(strings.ToLower(f.Name), "flex"))
	}
}

func Test_CreateKeyPair(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.CreateKeyPair(t)
}

func Test_CreateKeyPairAndLeave(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.CreateKeyPairAndLeaveItThere(t)
}

func Test_GetKeyPair(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.GetKeyPair(t)
}

func Test_ListKeyPairs(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.ListKeyPairs(t)
}

func Test_Networks(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.Networks(t)
}

func Test_NetworkCreation(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.CreateNetworkTest(t)
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

func Test_Volume(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.Volume(t)
}

func Test_VolumeAttachment(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.VolumeAttachment(t)
}

func Test_Containers(t *testing.T) {
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.Containers(t)
}

// func Test_Objects(t *testing.T) {
// 	cli, err := getTester()
// 	require.Nil(t, err)
// 	cli.Objects(t)
// }

// GetImage returns the Image referenced by id
func Test_GetImage(t *testing.T) {
	// TODO Implement Test
	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.GetImage(t)
}

// GetTemplate returns the Template referenced by id
func Test_GetTemplate(t *testing.T) {
	// TODO Implement Test

	cli, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	cli.GetTemplate(t)
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func Test_ListTemplates(t *testing.T) {
	// TODO Implement Test

}

// DeleteKeyPair deletes the key pair identified by id
func Test_DeleteKeyPair(t *testing.T) {
	// TODO Implement Test

}

// CreateNetwork creates a network named name
func Test_CreateNetwork(t *testing.T) {
	// TODO Implement Test

}

// GetNetwork returns the network identified by ref (id or name)
func Test_GetNetwork(t *testing.T) {
	// TODO Implement Test

}

// ListNetworks lists available networks
func Test_ListNetworks(t *testing.T) {
	// TODO Implement Test

}

// DeleteNetwork deletes the network identified by id
func Test_DeleteNetwork(t *testing.T) {
	// TODO Implement Test

}

// CreateGateway creates a public Gateway for a private network
func Test_CreateGateway(t *testing.T) {
	// TODO Implement Test

}

// DeleteGateway delete the public gateway of a private network
func Test_DeleteGateway(t *testing.T) {
	// TODO Implement Test

}

// CreateHost creates an host that fulfils the request
func Test_CreateHost(t *testing.T) {
	// TODO Implement Test

}

// GetHost returns the host identified by id
func Test_InspectHost(t *testing.T) {
	// TODO Implement Test

}

// ListHosts lists available hosts
func Test_ListHosts(t *testing.T) {
	// TODO Implement Test

}

// DeleteHost deletes the host identified by id
func Test_DeleteHost(t *testing.T) {
	// TODO Implement Test

}

// StopHost stops the host identified by id
func Test_StopHost(t *testing.T) {
	// TODO Implement Test

}

// StartHost starts the host identified by id
func Test_StartHost(t *testing.T) {
	// TODO Implement Test

}

// GetSSHConfig creates SSHConfig from host
func Test_GetSSHConfig(t *testing.T) {
	// TODO Implement Test

}

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func Test_CreateVolume(t *testing.T) {
	// TODO Implement Test

}

// GetVolume returns the volume identified by id
func Test_GetVolume(t *testing.T) {
	// TODO Implement Test

}

// ListVolumes list available volumes
func Test_ListVolumes(t *testing.T) {
	// TODO Implement Test

}

// DeleteVolume deletes the volume identified by id
func Test_DeleteVolume(t *testing.T) {
	// TODO Implement Test

}

// CreateVolumeAttachment attaches a volume to an host
//- name of the volume attachment
//- volume to attach
//- host on which the volume is attached
func Test_CreateVolumeAttachment(t *testing.T) {
	// TODO Implement Test

}

// GetVolumeAttachment returns the volume attachment identified by id
func Test_GetVolumeAttachment(t *testing.T) {
	// TODO Implement Test

}

// ListVolumeAttachments lists available volume attachment
func Test_ListVolumeAttachments(t *testing.T) {
	// TODO Implement Test

}

// DeleteVolumeAttachment deletes the volume attachment identifed by id
func Test_DeleteVolumeAttachment(t *testing.T) {
	// TODO Implement Test

}

// CreateContainer creates an object container
func Test_CreateContainer(t *testing.T) {
	// TODO Implement Test

}

// DeleteContainer deletes an object container
func Test_DeleteContainer(t *testing.T) {
	// TODO Implement Test

}

// ListContainers list object containers
func Test_ListContainers(t *testing.T) {
	// TODO Implement Test

}

// Getcontainer returns info of the container
func Test_GetContainer(t *testing.T) {
	// TODO Implement Test

}

// PutObject put an object into an object container
func Test_PutObject(t *testing.T) {
	// TODO Implement Test

}

// UpdateObjectMetadata update an object into  object container
func Test_UpdateObjectMetadata(t *testing.T) {
	// TODO Implement Test

}

// GetObject get  object content from an object container
func Test_GetObject(t *testing.T) {
	// TODO Implement Test

}

// GetObjectMetadata get  object metadata from an object container
func Test_GetObjectMetadata(t *testing.T) {
	// TODO Implement Test

}

// ListObjects list objects of a container
func Test_ListObjects(t *testing.T) {
	// TODO Implement Test

}

// CopyObject copies an object
func Test_CopyObject(t *testing.T) {
	// TODO Implement Test

}

// DeleteObject delete an object from a container
func Test_DeleteObject(t *testing.T) {
	// TODO Implement Test

}

// GetAuthOpts returns authentification options as a Config
func Test_GetAuthOpts(t *testing.T) {
	// TODO Implement Test

}

// GetCfgOpts returns configuration options as a Config
func Test_GetCfgOpts(t *testing.T) {
	// TODO Implement Test

}
