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
package ovh_test

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/mocks"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/tests"
)

var mock_tester *tests.ClientTester
var gmci *mocks.MockClientAPI

func GetMockService(t *testing.T, tenant string) (*providers.Service, error) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	if strings.Contains(tenant, "Ovh") {
		mci := mocks.NewMockClientAPI(mockCtrl)

		return &providers.Service{
			ClientAPI: mci,
		}, nil
	} else {
		return providers.GetService(tenant)
	}
}

func getMockableClient(t *testing.T) (*tests.ClientTester, *mocks.MockClientAPI, error) {
	if mock_tester == nil {
		tenant_name := "TestOvh"
		if tenant_override := os.Getenv("TEST_OVH"); tenant_override != "" {
			tenant_name = tenant_override
		}
		service, err := GetMockService(t, tenant_name)
		if err != nil {
			return nil, nil, errors.New(fmt.Sprintf("You must provide a VALID tenant [%v], check your environment variables and your Safescale configuration files", tenant_name))
		}
		mock_tester = &tests.ClientTester{
			Service: *service,
		}

		gmci_local, ok := service.ClientAPI.(*mocks.MockClientAPI)

		if ok {
			gmci = gmci_local
		}
	}
	return mock_tester, gmci, nil

}

// Helper function to test mock objects
func GetHostTemplate(core int, ram int, disk int) model.HostTemplate {
	return model.HostTemplate{
		Cores:    core,
		RAMSize:  float32(ram) / 1000.0,
		DiskSize: disk,
		ID:       "",
		Name:     "",
	}
}

// Test that we have templates, and each template has 1 or more cores
func TestMock_GetTemplates_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)

	// It runs with the Mock object
	if amok != nil {
		amok.EXPECT().ListTemplates(false).Times(1).Return([]model.HostTemplate{GetHostTemplate(3, 3, 1), GetHostTemplate(4, 4, 2)}, nil)
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

func TestMock_GetGpuTemplate_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	if amok != nil {
		// TODO Make it return a NVIDIA 1080 TI only for mocks
		// TODO Create HostTemplateGenerator
		amok.EXPECT().ListTemplates(false).Return(nil, nil)
		amok.EXPECT().GetTemplate("g3-120")
	}

	tpls, err := cli.Service.ListTemplates(false)
	assert.NoError(t, err)

	_, err = cli.Service.GetTemplate("g3-120")

	if err == nil {
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

func TestMock_ListImages_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	if amok != nil {
		amok.EXPECT().ListImages(false).Return([]model.Image{{ID: "I1", Name: "Ubuntu"}, {ID: "I2", Name: "Debian"}}, nil).AnyTimes()
	}

	cli.ListImages(t)
}

func TestMock_ListHostTemplates_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	if amok != nil {
		ht := &model.HostTemplate{
			ID:    "ID1",
			Name:  "TemplateUbuntu",
			Cores: 1,
		}

		amok.EXPECT().ListTemplates(false).Return([]*model.HostTemplate{ht}, nil).AnyTimes()
		amok.EXPECT().ListImages(false).Return([]model.Image{{ID: "I1", Name: "Ubuntu"}, {ID: "I2", Name: "Debian"}}, nil).AnyTimes()
	}

	cli.ListHostTemplates(t)
	tpls, err := cli.Service.ListTemplates(false)
	assert.Nil(t, err)
	assert.NotEmpty(t, tpls)
	for _, f := range tpls {
		assert.True(t, !strings.HasPrefix(strings.ToLower(f.Name), "win"))
		assert.True(t, !strings.HasSuffix(strings.ToLower(f.Name), "flex"))
	}
}

func TestMock_CreateKeyPair_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	if amok != nil {
		amok.EXPECT().CreateKeyPair("kp").Return(&model.KeyPair{ID: "1", Name: "2", PublicKey: "3", PrivateKey: "4"}, nil)
		amok.EXPECT().DeleteKeyPair("1").Return(nil)
	}

	cli.CreateKeyPair(t)
}

func TestMock_CreateKeyPairAndLeave_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	// TODO use Mock object
	_ = amok

	cli.CreateKeyPairAndLeaveItThere(t)
}

func TestMock_GetKeyPair_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	// TODO use Mock object
	_ = amok

	cli.GetKeyPair(t)
}

func TestMock_ListKeyPairs_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	// TODO use Mock object
	_ = amok

	cli.ListKeyPairs(t)
}

func TestMock_Networks_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	// TODO use Mock object
	_ = amok

	cli.Networks(t)
}

func TestMock_NetworkCreation_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	// TODO use Mock object
	_ = amok

	cli.CreateNetworkTest(t)
}

func TestMock_Hosts_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	// TODO use Mock object
	_ = amok

	cli.Hosts(t)
}

func TestMock_StartStopHost_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	// TODO use Mock object
	_ = amok

	cli.StartStopHost(t)
}

func TestMock_Volume_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	// TODO use Mock object
	_ = amok

	cli.Volume(t)
}

func TestMock_VolumeAttachment_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	// TODO use Mock object
	_ = amok
	cli.VolumeAttachment(t)
}

func TestMock_Containers_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	// TODO use Mock object
	_ = amok

	cli.Containers(t)
}

func TestMock_Objects_Mock(t *testing.T) {
	cli, amok, err := getMockableClient(t)
	require.Nil(t, err)

	// TODO use Mock object
	_ = amok

	cli.Objects(t)
}

// ListImages lists available OS images
func TestMock_ListImages(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// GetImage returns the Image referenced by id
func TestMock_GetImage(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// GetTemplate returns the Template referenced by id
func TestMock_GetTemplate(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func TestMock_ListTemplates(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// CreateKeyPair creates and import a key pair
func TestMock_CreateKeyPair(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// GetKeyPair returns the key pair identified by id
func TestMock_GetKeyPair(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// ListKeyPairs lists available key pairs
func TestMock_ListKeyPairs(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// DeleteKeyPair deletes the key pair identified by id
func TestMock_DeleteKeyPair(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// CreateNetwork creates a network named name
func TestMock_CreateNetwork(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// GetNetwork returns the network identified by ref (id or name)
func TestMock_GetNetwork(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// ListNetworks lists available networks
func TestMock_ListNetworks(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// DeleteNetwork deletes the network identified by id
func TestMock_DeleteNetwork(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// CreateGateway creates a public Gateway for a private network
func TestMock_CreateGateway(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// DeleteGateway delete the public gateway of a private network
func TestMock_DeleteGateway(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// CreateHost creates an host that fulfils the request
func TestMock_CreateHost(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// GetHost returns the host identified by id
func TestMock_GetHost(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// ListHosts lists available hosts
func TestMock_ListHosts(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// DeleteHost deletes the host identified by id
func TestMock_DeleteHost(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// StopHost stops the host identified by id
func TestMock_StopHost(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// StartHost starts the host identified by id
func TestMock_StartHost(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// GetSSHConfig creates SSHConfig from host
func TestMock_GetSSHConfig(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func TestMock_CreateVolume(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// GetVolume returns the volume identified by id
func TestMock_GetVolume(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// ListVolumes list available volumes
func TestMock_ListVolumes(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// DeleteVolume deletes the volume identified by id
func TestMock_DeleteVolume(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// CreateVolumeAttachment attaches a volume to an host
//- name of the volume attachment
//- volume to attach
//- host on which the volume is attached
func TestMock_CreateVolumeAttachment(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// GetVolumeAttachment returns the volume attachment identified by id
func TestMock_GetVolumeAttachment(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// ListVolumeAttachments lists available volume attachment
func TestMock_ListVolumeAttachments(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// DeleteVolumeAttachment deletes the volume attachment identifed by id
func TestMock_DeleteVolumeAttachment(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// CreateContainer creates an object container
func TestMock_CreateContainer(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// DeleteContainer deletes an object container
func TestMock_DeleteContainer(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// ListContainers list object containers
func TestMock_ListContainers(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// Getcontainer returns info of the container
func TestMock_GetContainer(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// PutObject put an object into an object container
func TestMock_PutObject(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// UpdateObjectMetadata update an object into  object container
func TestMock_UpdateObjectMetadata(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// GetObject get  object content from an object container
func TestMock_GetObject(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// GetObjectMetadata get  object metadata from an object container
func TestMock_GetObjectMetadata(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// ListObjects list objects of a container
func TestMock_ListObjects(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// CopyObject copies an object
func TestMock_CopyObject(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// DeleteObject delete an object from a container
func TestMock_DeleteObject(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// GetAuthOpts returns authentification options as a Config
func TestMock_GetAuthOpts(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}

// GetCfgOpts returns configuration options as a Config
func TestMock_GetCfgOpts(t *testing.T) {
	// TODO Implement Test
	// TODO use Mock object
}
