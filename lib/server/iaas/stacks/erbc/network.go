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

package erbc

import (
	"github.com/CS-SI/SafeScale/iaas/resources"
)

// CreateNetwork creates a network named name
func (s *StackErbc) CreateNetwork(req resources.NetworkRequest) (*resources.Network, error) {
	panic("implement me")
}

// GetNetwork returns the network identified by ref (id or name)
func (s *StackErbc) GetNetwork(ref string) (*resources.Network, error) {
	panic("implement me")
}

// GetNetworkByName returns the network identified by ref (id or name)
func (s *StackErbc) GetNetworkByName(ref string) (*resources.Network, error) {
	panic("implement me")
}

// ListNetworks lists available networks
func (s *StackErbc) ListNetworks() ([]*resources.Network, error) {
	panic("implement me")
}

// DeleteNetwork deletes the network identified by id
func (s *StackErbc) DeleteNetwork(ref string) error {
	panic("implement me")
}

// CreateGateway creates a public Gateway for a private network
func (s *StackErbc) CreateGateway(req resources.GatewayRequest) (*resources.Host, error) {
	panic("implement me")
}

// DeleteGateway delete the public gateway referenced by ref (id or name)
func (s *StackErbc) DeleteGateway(ref string) error {
	panic("implement me")
}
