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

package handlers

//FIXME: iaas.Service became an interface, so can't be used as before.
//       Need to write a service struct satisfying iaas.Service interface
//       and then initializes an instance of this service struct
//
// func TestNetworkHandler_List_with_safescaled_running(t *testing.T) {
// 	mockCtrl := gomock.NewController(t)
// 	defer mockCtrl.Finish()

// 	mockClientAPI := mocks.NewMockProvider(mockCtrl)

// 	ness := &NetworkHandler{
// 		service: iaas.Service{
// 			Provider: mockClientAPI,
// 		},
// 	}

// 	mockClientAPI.EXPECT().ListNetworks().Return(nil, nil).Times(1)

// 	result, daerr := ness.service.ListNetworks()
// 	assert.Nil(t, daerr)

// 	_ = result
// }

// func TestNetworkHandler_List_with_NO_safescaled_running(t *testing.T) {
// 	mockCtrl := gomock.NewController(t)
// 	defer mockCtrl.Finish()

// 	safescaledPort := 50051

// 	if portCandidate := os.Getenv("SAFESCALED_PORT"); portCandidate != "" {
// 		num, err := strconv.Atoi(portCandidate)
// 		if err == nil {
// 			safescaledPort = num
// 		}
// 	}

// 	mockClientAPI := mocks.NewMockProvider(mockCtrl)
// 	theError := fmt.Errorf("Could not get network list: rpc error: code = Unavailable desc = all SubConns are in TransientFailure, latest connection error: connection error: desc = \"transport: Error while dialing dial tcp 127.0.0.1:%s: connect: connection refused\"", strconv.Itoa(safescaledPort))

// 	ness := &NetworkHandler{
// 		service: iaas.Service{
// 			Provider: mockClientAPI,
// 		},
// 	}

// 	mockClientAPI.EXPECT().ListNetworks().Return(nil, theError).Times(1)

// 	result, daerr := ness.service.ListNetworks()
// 	assert.NotNil(t, daerr)

// 	assert.True(t, strings.Contains(daerr.Error(), "TransientFailure"))

// 	assert.Nil(t, result)
// }
