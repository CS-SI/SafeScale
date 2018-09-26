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
package commands_test

import (
	"errors"
	"github.com/CS-SI/SafeScale/providers/api/enums/VolumeSpeed"
	"testing"

	"github.com/CS-SI/SafeScale/providers"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/daemon/commands"
	"github.com/CS-SI/SafeScale/broker/daemon/services"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MyMockedVolService struct {
	mock.Mock
	err error
}

func (m *MyMockedVolService) Create(name string, size int, speed VolumeSpeed.Enum) (*api.Volume, error) {
	m.Called(name, size, speed)

	return &api.Volume{Name: name,
		Size:  size,
		Speed: speed}, m.err
}
func (m *MyMockedVolService) Delete(name string) error {
	return nil
}
func (m *MyMockedVolService) List() ([]api.Volume, error) {
	return nil, nil
}
func (m *MyMockedVolService) Attach(volume string, host string, path string, format string) error {
	return nil
}
func (m *MyMockedVolService) Detach(volume string, host string) error {
	return nil
}
func (m *MyMockedVolService) Get(ref string) (*api.Volume, error) {
	return &api.Volume{}, nil
}

func TestCreate(t *testing.T) {
	// ARRANGE
	myMockedVolService := &MyMockedVolService{}
	myMockedVolService.On("Create", mock.Anything, mock.Anything, mock.Anything).Return()
	//Mock VolumeServiceCreator
	old := commands.VolumeServiceCreator
	defer func() { commands.VolumeServiceCreator = old }()

	commands.VolumeServiceCreator = func(api api.ClientAPI) services.VolumeAPI {
		return nil
		// TODO Fix this
		// return myMockedVolService
	}

	// Mock GetCurrentTenant
	oldGetCurrentTeant := commands.GetCurrentTenant
	defer func() { commands.GetCurrentTenant = oldGetCurrentTeant }()
	commands.GetCurrentTenant = func() *commands.Tenant {
		return &commands.Tenant{Client: &providers.Service{}}
	}

	underTest := &commands.VolumeServiceServer{}

	// ACT
	underTest.Create(nil, &pb.VolumeDefinition{
		Speed: pb.VolumeSpeed_SSD,
	})
	// ASSERT
	myMockedVolService.AssertCalled(t, "Create", mock.Anything, mock.Anything, VolumeSpeed.SSD)

	underTest.Create(nil, &pb.VolumeDefinition{
		Speed: pb.VolumeSpeed_HDD,
	})
	myMockedVolService.AssertCalled(t, "Create", mock.Anything, mock.Anything, VolumeSpeed.HDD)
	underTest.Create(nil, &pb.VolumeDefinition{
		Speed: pb.VolumeSpeed_COLD,
	})
	myMockedVolService.AssertCalled(t, "Create", mock.Anything, mock.Anything, VolumeSpeed.COLD)
}

func TestCreate_Err(t *testing.T) {
	// ARRANGE
	myMockedVolService := &MyMockedVolService{err: errors.New("plop")}
	myMockedVolService.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("Fake Error"))
	//Mock VolumeServiceCreator
	old := commands.VolumeServiceCreator
	defer func() { commands.VolumeServiceCreator = old }()

	commands.VolumeServiceCreator = func(api api.ClientAPI) services.VolumeAPI {
		// TODO Fix this
		return nil
		// return myMockedVolService
	}

	// Mock GetCurrentTenant
	oldGetCurrentTeant := commands.GetCurrentTenant
	defer func() { commands.GetCurrentTenant = oldGetCurrentTeant }()
	commands.GetCurrentTenant = func() *commands.Tenant {
		return &commands.Tenant{Client: &providers.Service{}}
	}

	underTest := &commands.VolumeServiceServer{}

	// ACT
	_, err := underTest.Create(nil, &pb.VolumeDefinition{
		Speed: pb.VolumeSpeed_SSD,
	})
	// ASSERT
	myMockedVolService.AssertExpectations(t)
	assert.NotNil(t, err)
}

func TestCreate_Err_NoTenantSet(t *testing.T) {
	// ARRANGE
	// Mock GetCurrentTenant
	oldGetCurrentTeant := commands.GetCurrentTenant
	defer func() { commands.GetCurrentTenant = oldGetCurrentTeant }()
	commands.GetCurrentTenant = func() *commands.Tenant {
		return nil
	}
	myMockedVolService := &MyMockedVolService{err: errors.New("plop")}
	underTest := &commands.VolumeServiceServer{}

	// ACT
	_, err := underTest.Create(nil, &pb.VolumeDefinition{
		Speed: pb.VolumeSpeed_SSD,
	})
	// ASSERT
	myMockedVolService.AssertNotCalled(t, "Create")
	assert.EqualError(t, err, "No tenant set")
}
