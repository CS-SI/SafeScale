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
package listeners_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/lib/server/listeners"
)

type MyMockedVolService struct {
	mock.Mock
	err error
}

func (m *MyMockedVolService) Create(name string, size int, speed VolumeSpeed.Enum) (*resources.Volume, error) {
	m.Called(name, size, speed)

	return &resources.Volume{Name: name,
		Size:  size,
		Speed: speed}, m.err
}
func (m *MyMockedVolService) Delete(name string) error {
	return nil
}
func (m *MyMockedVolService) List() ([]resources.Volume, error) {
	return nil, nil
}
func (m *MyMockedVolService) Attach(volume string, host string, path string, format string) error {
	return nil
}
func (m *MyMockedVolService) Detach(volume string, host string) error {
	return nil
}
func (m *MyMockedVolService) Get(ref string) (*resources.Volume, error) {
	return &resources.Volume{}, nil
}

func TestCreate(t *testing.T) {
	// ARRANGE
	myMockedVolService := &MyMockedVolService{}
	myMockedVolService.On("Create", mock.Anything, mock.Anything, mock.Anything).Return()
	//Mock VolumeServiceCreator
	old := listeners.VolumeHandler
	defer func() { listeners.VolumeHandler = old }()

	listeners.VolumeHandler = func(svc iaas.Service) handlers.VolumeAPI {
		return nil
		// TODO Fix this test
		// return myMockedVolService
	}

	// Mock GetCurrentTenant
	oldGetCurrentTeant := listeners.GetCurrentTenant
	defer func() { listeners.GetCurrentTenant = oldGetCurrentTeant }()
	listeners.GetCurrentTenant = func() *listeners.Tenant {
		return &listeners.Tenant{}
	}

	underTest := &listeners.VolumeListener{}

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
	old := listeners.VolumeHandler
	defer func() { listeners.VolumeHandler = old }()

	listeners.VolumeHandler = func(api iaas.Service) handlers.VolumeAPI {
		// TODO Fix this test
		return nil
		// return myMockedVolService
	}

	// Mock GetCurrentTenant
	oldGetCurrentTeant := listeners.GetCurrentTenant
	defer func() { listeners.GetCurrentTenant = oldGetCurrentTeant }()
	listeners.GetCurrentTenant = func() *listeners.Tenant {
		return &listeners.Tenant{}
	}

	underTest := &listeners.VolumeListener{}

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
	oldGetCurrentTeant := listeners.GetCurrentTenant
	defer func() { listeners.GetCurrentTenant = oldGetCurrentTeant }()
	listeners.GetCurrentTenant = func() *listeners.Tenant {
		return nil
	}
	myMockedVolService := &MyMockedVolService{err: errors.New("plop")}
	underTest := &listeners.VolumeListener{}

	// ACT
	_, err := underTest.Create(nil, &pb.VolumeDefinition{
		Speed: pb.VolumeSpeed_SSD,
	})
	// ASSERT
	myMockedVolService.AssertNotCalled(t, "Create")
	assert.EqualError(t, err, "No tenant set")
}
