/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package openstack

import (
	"encoding/json"
	"strings"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

func (s Stack) rpcGetHostByID(id string) (*servers.Server, fail.Error) {
	nullServer := &servers.Server{}
	if id == "" {
		return nullServer, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	var server *servers.Server
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			server, err = servers.Get(s.ComputeClient, id).Extract()
			return err
		},
		NormalizeError,
	)
	if xerr != nil {
		return nullServer, xerr
	}
	return server, nil
}

func (s Stack) rpcGetHostByName(name string) (*servers.Server, fail.Error) {
	nullServer := &servers.Server{}
	if name = strings.TrimSpace(name); name == "" {
		return nullServer, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
	r := servers.GetResult{}
	xerr := stacks.RetryableRemoteCall(
		func() error {
			_, r.Err = s.ComputeClient.Get(s.ComputeClient.ServiceURL("servers?name="+name), &r.Body, &gophercloud.RequestOpts{
				OkCodes: []int{200, 203},
			})
			return r.Err
		},
		NormalizeError,
	)
	if xerr != nil {
		return nullServer, xerr
	}

	jsoned, err := json.Marshal(r.Body.(map[string]interface{})["servers"])
	if err != nil {
		return nullServer, fail.SyntaxError(err.Error())
	}
	var resp []*servers.Server
	if err = json.Unmarshal(jsoned, &resp); err != nil {
		return nullServer, fail.SyntaxError(err.Error())
	}
	if len(resp) == 0 {
		return nullServer, fail.NotFoundError("failed to find a Host named '%s'", name)
	}
	if len(resp) > 1 {
		return nullServer, fail.InconsistentError("found more than one Host named '%s'", name)
	}
	return resp[0], nil

	// serverList, found := r.Body.(map[string]interface{})["servers"].([]interface{})
	// if found && len(serverList) > 0 {
	// 	for _, anon := range serverList {
	// 		entry := anon.(map[string]interface{})
	// 		if entry["name"].(string) == ahf.Core.Name {
	// 			host := abstract.NewHostCore()
	// 			host.ID = entry["id"].(string)
	// 			host.Name = name
	// 			hostFull, xerr := s.InspectHost(host)
	// 			if xerr != nil {
	// 				return nullAHF, fail.Wrap(xerr, "failed to inspect host '%s'", name)
	// 			}
	// 			return hostFull, nil
	// 		}
	// 	}
	// }
}

// rpcGetMetadataOfInstance returns the metadata associated with the instance
func (s Stack) rpcGetMetadataOfInstance(id string) (map[string]string, fail.Error) {
	emptyMap := map[string]string{}
	if id = strings.TrimSpace(id); id == "" {
		return emptyMap, fail.InvalidParameterError("id", "cannpt be empty string")
	}

	var out map[string]string
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			res := servers.Metadata(s.ComputeClient, id)
			out, innerErr = res.Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return emptyMap, xerr
		default:
			return emptyMap, xerr
		}
	}

	return out, nil
}

// rpcListServers lists servers
func (s Stack) rpcListServers() ([]*servers.Server, fail.Error) {
	var resp []*servers.Server
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			allPages, innerErr := servers.List(s.ComputeClient, nil).AllPages()
			if innerErr != nil {
				return innerErr
			}
			if innerErr := servers.ExtractServersInto(allPages, &resp); innerErr != nil {
				return innerErr
			}
			return nil
		},
		NormalizeError,
	)
	if xerr != nil {
		return []*servers.Server{}, xerr
	}

	return resp, nil
}

// rpcCreateServer calls openstack to create a server
func (s Stack) rpcCreateServer(name string, networks []servers.Network, templateID, imageID string, userdata []byte, az string) (*servers.Server, fail.Error) {
	nullServer := &servers.Server{}
	if name = strings.TrimSpace(name); name == "" {
		return nullServer, fail.InvalidParameterCannotBeEmptyStringError("name")
	}
	if templateID = strings.TrimSpace(templateID); templateID == "" {
		return nullServer, fail.InvalidParameterCannotBeEmptyStringError("templateID")
	}
	if imageID = strings.TrimSpace(imageID); imageID == "" {
		return nullServer, fail.InvalidParameterCannotBeEmptyStringError("imageID")
	}
	if az == "" {
		return nullServer, fail.InvalidParameterCannotBeEmptyStringError("az")
	}

	srvOpts := servers.CreateOpts{
		Name:             name,
		Networks:         networks,
		FlavorRef:        templateID,
		ImageRef:         imageID,
		UserData:         userdata,
		AvailabilityZone: az,
	}

	var server *servers.Server
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			server, innerErr = servers.Create(s.ComputeClient, srvOpts).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return &servers.Server{}, xerr
	}
	return server, nil
}

// rpcDeleteServer calls openstack to delete a server
func (s Stack) rpcDeleteServer(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	return stacks.RetryableRemoteCall(
		func() error {
			return servers.Delete(s.ComputeClient, id).ExtractErr()
		},
		NormalizeError,
	)
}

// rpcCreatePort creates a port
func (s Stack) rpcCreatePort(req ports.CreateOpts) (port *ports.Port, xerr fail.Error) {
	xerr = stacks.RetryableRemoteCall(
		func() (innerErr error) {
			port, innerErr = ports.Create(s.NetworkClient, req).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	return port, nil
}

// rpcDeletePort deletes a port
func (s Stack) rpcDeletePort(id string) fail.Error {
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	return stacks.RetryableRemoteCall(
		func() (innerErr error) {
			return ports.Delete(s.NetworkClient, id).ExtractErr()
		},
		NormalizeError,
	)
}

// rpcListPorts lists all ports available
func (s Stack) rpcListPorts(options ports.ListOpts) ([]ports.Port, fail.Error) {
	var (
		emptyList []ports.Port
		allPages  pagination.Page
	)
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			allPages, innerErr = ports.List(s.NetworkClient, options).AllPages()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return emptyList, xerr
	}

	r, err := ports.ExtractPorts(allPages)
	if err != nil {
		return emptyList, NormalizeError(err)
	}
	return r, nil
}

// rpcUpdatePort updates the settings of a port
func (s Stack) rpcUpdatePort(id string, options ports.UpdateOpts) fail.Error {
	if id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	return stacks.RetryableRemoteCall(
		func() error {
			resp, innerErr := ports.Update(s.NetworkClient, id, options).Extract()
			_ = resp
			return innerErr
		},
		NormalizeError,
	)
}

// rpcGetPort returns port information from its ID
func (s Stack) rpcGetPort(id string) (port *ports.Port, xerr fail.Error) {
	nullPort := &ports.Port{}

	if id == "" {
		return nullPort, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	xerr = stacks.RetryableRemoteCall(
		func() (innerErr error) {
			port, innerErr = ports.Get(s.NetworkClient, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nullPort, xerr
	}

	return port, nil
}

// rpcCreateFloatingIP creates a floating IP
func (s Stack) rpcCreateFloatingIP() (*floatingips.FloatingIP, fail.Error) {
	var resp *floatingips.FloatingIP
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, innerErr = floatingips.Create(s.ComputeClient, floatingips.CreateOpts{
				Pool: s.authOpts.FloatingIPPool,
			}).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return &floatingips.FloatingIP{}, xerr
	}
	return resp, nil
}

// rpcDeleteFloatingIP deletes a floating IP
func (s Stack) rpcDeleteFloatingIP(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	return stacks.RetryableRemoteCall(
		func() error {
			return floatingips.Delete(s.ComputeClient, id).ExtractErr()
		},
		NormalizeError,
	)
}
