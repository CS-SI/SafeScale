/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package outscale

import (
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hostproperty"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/abstract/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/userdata"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// CreateGateway creates a public Gateway for a private network
func (s *Stack) CreateGateway(req abstract.GatewayRequest, sizing *abstract.SizingRequirements) (*abstract.Host, *userdata.Content, error) {
	userData := userdata.NewContent()

	// Ensure network exists
	if req.Network == nil {
		return nil, nil, fail.InvalidParameterError("req.Network", "cannot be nil")
	}
	gwname := strings.Split(req.Name, ".")[0] // req.Name may contain a FQDN...
	if gwname == "" {
		gwname = "gw-" + req.Network.Name
	}

	password, err := utils.GeneratePassword(16)
	if err != nil {
		return nil, userData, fail.Wrap(err, fmt.Sprintf("failed to generate password: %s", err.Error()))
	}
	hostReq := abstract.HostRequest{
		ImageID:      req.ImageID,
		KeyPair:      req.KeyPair,
		HostName:     req.Name,
		ResourceName: gwname,
		TemplateID:   req.TemplateID,
		Networks:     []*abstract.Network{req.Network},
		PublicIP:     true,
		Password:     password,
	}
	if sizing != nil && sizing.MinDiskSize > 0 {
		hostReq.DiskSize = sizing.MinDiskSize
	}
	host, userData, err := s.CreateHost(hostReq)
	if err != nil {
		return nil, nil, fail.Wrap(err, fmt.Sprintf("error creating gateway : %v", err))
	}
	if host == nil {
		return nil, nil, fail.InconsistentError("host creation returned with an empty host and without reporting an error")
	}

	// Updates Host Property propsv1.HostSizing
	err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(
		func(clonable data.Clonable) error {
			hostSizingV1 := clonable.(*propsv1.HostSizing)
			hostSizingV1.Template = req.TemplateID
			return nil
		},
	)
	if err != nil {
		return nil, userData, fail.Wrap(err, fmt.Sprintf("error creating gateway : %v", err))
	}
	return host, userData, nil
}

// DeleteGateway delete the public gateway of a private network
func (s *Stack) DeleteGateway(id string) error {
	return s.DeleteHost(id)
}
