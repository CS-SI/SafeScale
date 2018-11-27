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

package services

import (
	"testing"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/mocks"
	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestNetworkService_List_with_brokerd_running(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockClientAPI := mocks.NewMockClientAPI(mockCtrl)

	ness := &NetworkService{
		provider: &providers.Service{
			ClientAPI: mockClientAPI,
		},
	}

	mockClientAPI.EXPECT().ListNetworks().Return(nil, nil).Times(1)

	result, daerr := ness.provider.ListNetworks()

	assert.Nil(t, daerr)

	_ = result
}

func TestNetworkService_List_with_NO_brokerd_running(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockClientAPI := mocks.NewMockClientAPI(mockCtrl)
	theError := errors.New("Could not get network list: rpc error: code = Unavailable desc = all SubConns are in TransientFailure, latest connection error: connection error: desc = \"transport: Error while dialing dial tcp 127.0.0.1:50051: connect: connection refused\"")

	ness := &NetworkService{
		provider: &providers.Service{
			ClientAPI: mockClientAPI,
		},
	}

	mockClientAPI.EXPECT().ListNetworks().Return(nil, theError).Times(1)

	result, daerr := ness.provider.ListNetworks()

	assert.EqualError(t, daerr, "Failure")

	assert.Nil(t, result)
}
