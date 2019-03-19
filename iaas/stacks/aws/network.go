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

package aws

import (
	"fmt"

	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/CS-SI/SafeScale/iaas/resources"
)

// CreateNetwork creates a network
func (s *Stack) CreateNetwork(req resources.NetworkRequest) (*resources.Network, error) {
	panic("implement me")
}

// GetNetwork returns the network identified by id
func (s *Stack) GetNetwork(id string) (*resources.Network, error) {
	panic("implement me")
}

// ListNetworks lists available networks
func (s *Stack) ListNetworks() ([]*resources.Network, error) {
	panic("implement me")
}

// DeleteNetwork deletes the network identified by id
func (s *Stack) DeleteNetwork(id string) error {
	panic("implement me")
}

// CreateGateway exists only to comply with api.ClientAPI interface
func (s *Stack) CreateGateway(req resources.GatewayRequest) (*resources.Host, error) {
	return nil, fmt.Errorf("aws.CreateGateway() isn't available by design")
}

// DeleteGateway exists only to comply with api.ClientAPI interface
func (s *Stack) DeleteGateway(networkID string) error {
	return fmt.Errorf("aws.DeleteGateway() isn't available by design")
}

func (s *Stack) getSubnets(vpcIDs []*resources.Network) ([]*ec2.Subnet, error) {
	panic("implement me")
}
