/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package huaweicloud

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
)

func (s stack) rpcGetHostByID(id string) (*servers.Server, fail.Error) {
	if id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("id")
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
		return nil, xerr
	}
	return server, nil
}

func closer(hr *http.Response) {
	if hr != nil {
		if hr.Body != nil {
			_ = hr.Body.Close()
		}
	}
}

func (s stack) rpcGetHostByName(name string) (*servers.Server, fail.Error) {
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
	r := servers.GetResult{}
	xerr := stacks.RetryableRemoteCall(
		func() error {
			var hr *http.Response
			hr, r.Err = s.ComputeClient.Get( // nolint
				s.ComputeClient.ServiceURL("servers?name="+name), &r.Body, &gophercloud.RequestOpts{
					OkCodes: []int{200, 203},
				},
			)
			if r.Err != nil {
				return r.Err
			}
			defer closer(hr)
			return nil
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	jsoned, err := json.Marshal(r.Body.(map[string]interface{})["servers"])
	if err != nil {
		return nil, fail.SyntaxError(err.Error())
	}
	var resp []*servers.Server
	if err = json.Unmarshal(jsoned, &resp); err != nil {
		return nil, fail.SyntaxError(err.Error())
	}

	switch len(resp) {
	case 0:
		return nil, fail.NotFoundError("failed to find a Host named '%s'", name)
	default:
	}

	var (
		instance *servers.Server
		found    uint
	)
	for _, v := range resp {
		if v.Name == name {
			found++
			instance = v
		}
	}
	switch found {
	case 0:
		return nil, fail.NotFoundError("failed to find a Host named '%s'", name)
	case 1:
		return instance, nil
	}
	return nil, fail.InconsistentError("found more than one Host named '%s'", name)
}

// rpcGetMetadataOfInstance returns the metadata associated with the instance
func (s stack) rpcGetMetadataOfInstance(id string) (map[string]string, fail.Error) {
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
			return emptyMap, fail.Wrap(fail.Cause(xerr), "timeout")
		case *retry.ErrStopRetry:
			return emptyMap, fail.Wrap(fail.Cause(xerr), "stopping retries")
		default:
			return emptyMap, xerr
		}
	}

	return out, nil
}

// rpcListServers lists servers
func (s stack) rpcListServers() ([]*servers.Server, fail.Error) {
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
func (s stack) rpcCreateServer(name string, networks []servers.Network, templateID, imageID string, userdata []byte, az string) (*servers.Server, fail.Error) {
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}
	if templateID = strings.TrimSpace(templateID); templateID == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("templateID")
	}
	if imageID = strings.TrimSpace(imageID); imageID == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("imageID")
	}
	if az == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("az")
	}

	metadata := make(map[string]string)
	metadata["ManagedBy"] = "safescale"
	metadata["DeclaredInBucket"] = s.cfgOpts.MetadataBucket
	metadata["Image"] = imageID
	metadata["Template"] = templateID
	metadata["CreationDate"] = time.Now().Format(time.RFC3339)

	srvOpts := servers.CreateOpts{
		Name:             name,
		Networks:         networks,
		FlavorRef:        templateID,
		ImageRef:         imageID,
		UserData:         userdata,
		AvailabilityZone: az,
		Metadata:         metadata,
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
func (s stack) rpcDeleteServer(id string) fail.Error {
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
func (s stack) rpcCreatePort(req ports.CreateOpts) (port *ports.Port, ferr fail.Error) {
	xerr := stacks.RetryableRemoteCall(
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
func (s stack) rpcDeletePort(id string) fail.Error {
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
func (s stack) rpcListPorts(options ports.ListOpts) ([]ports.Port, fail.Error) {
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
func (s stack) rpcUpdatePort(id string, options ports.UpdateOpts) fail.Error {
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
func (s stack) rpcGetPort(id string) (port *ports.Port, ferr fail.Error) {
	if id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			port, innerErr = ports.Get(s.NetworkClient, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	return port, nil
}

// rpcCreateFloatingIP creates a floating IP
func (s stack) rpcCreateFloatingIP() (*floatingips.FloatingIP, fail.Error) {
	var resp *floatingips.FloatingIP
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, innerErr = floatingips.Create(
				s.ComputeClient, floatingips.CreateOpts{
					Pool: s.authOpts.FloatingIPPool,
				},
			).Extract()
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
func (s stack) rpcDeleteFloatingIP(id string) fail.Error {
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
