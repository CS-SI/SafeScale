/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"encoding/json"
	"github.com/CS-SI/SafeScale/v22/lib"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/bootfromvolume"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/portsecurity"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/pagination"
)

func (s stack) rpcGetHostByID(ctx context.Context, id string) (*servers.Server, fail.Error) {
	if id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	var server *servers.Server
	xerr := stacks.RetryableRemoteCall(ctx,
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

func (s stack) rpcGetHostByName(ctx context.Context, name string) (*servers.Server, fail.Error) {
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
	r := servers.GetResult{}
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			_, r.Err = s.ComputeClient.Get(
				s.ComputeClient.ServiceURL("servers?name="+name), &r.Body, &gophercloud.RequestOpts{
					OkCodes: []int{200, 203},
				},
			)
			return r.Err
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
func (s stack) rpcGetMetadataOfInstance(ctx context.Context, id string) (map[string]string, fail.Error) {
	if id = strings.TrimSpace(id); id == "" {
		return nil, fail.InvalidParameterError("id", "cannpt be empty string")
	}

	var out map[string]string
	xerr := stacks.RetryableRemoteCall(ctx,
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
			return nil, fail.Wrap(fail.Cause(xerr), "timeout")
		case *retry.ErrStopRetry:
			return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		default:
			return nil, xerr
		}
	}

	return out, nil
}

// rpcSetMetadataOfInstance changes the metadata associated with the instance
func (s stack) rpcSetMetadataOfInstance(ctx context.Context, id string, tags map[string]string) fail.Error {
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	var out map[string]string
	xerr := stacks.RetryableRemoteCall(ctx,
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
			return fail.Wrap(fail.Cause(xerr), "timeout")
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		default:
			return xerr
		}
	}

	for k, v := range tags {
		out[k] = v
	}

	mop := make(servers.MetadataOpts)
	for k, v := range out {
		mop[k] = v
	}

	xerr = stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			res := servers.UpdateMetadata(s.ComputeClient, id, mop)
			_, innerErr = res.Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return fail.Wrap(fail.Cause(xerr), "timeout")
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		default:
			return xerr
		}
	}

	return nil
}

// rpcDeleteMetadataOfInstance changes the metadata associated with the instance
func (s stack) rpcDeleteMetadataOfInstance(ctx context.Context, id string, tags map[string]string) fail.Error {
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			for k := range tags {
				res := servers.DeleteMetadatum(s.ComputeClient, id, k)
				innerErr = res.ExtractErr()
				return innerErr
			}
			return nil
		},
		NormalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return fail.Wrap(fail.Cause(xerr), "timeout")
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		default:
			return xerr
		}
	}

	return nil
}

// rpcListServers lists servers
func (s stack) rpcListServers(ctx context.Context) ([]*servers.Server, fail.Error) {
	var resp []*servers.Server
	xerr := stacks.RetryableRemoteCall(ctx,
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
func (s stack) rpcCreateServer(ctx context.Context, name string, networks []servers.Network, templateID, imageID string, diskSize int, userdata []byte, az string) (*servers.Server, fail.Error) {
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
	metadata["Revision"] = lib.Revision

	srvOpts := servers.CreateOpts{
		Name:             name,
		ImageRef:         imageID,
		FlavorRef:        templateID,
		UserData:         userdata,
		AvailabilityZone: az,
		Networks:         networks,
		Metadata:         metadata,
	}

	bd := []bootfromvolume.BlockDevice{
		{
			UUID:       srvOpts.ImageRef,
			SourceType: bootfromvolume.SourceImage,
			VolumeSize: diskSize,
		},
	}

	var server *servers.Server
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			aserver, innerErr := bootfromvolume.Create(s.ComputeClient, bootfromvolume.CreateOptsExt{
				CreateOptsBuilder: srvOpts,
				BlockDevice:       bd,
			}).Extract()
			if innerErr != nil {
				return innerErr
			}
			server = aserver
			return nil
		},
		NormalizeError,
	)
	if xerr != nil {
		return &servers.Server{}, xerr
	}

	if server == nil {
		return nil, fail.NewError("invalid server")
	}
	if server.ID == "" {
		return nil, fail.NewError("invalid server")
	}

	return server, nil
}

// rpcDeleteServer calls openstack to delete a server
func (s stack) rpcDeleteServer(ctx context.Context, id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return servers.Delete(s.ComputeClient, id).ExtractErr()
		},
		NormalizeError,
	)
}

// rpcCreatePort creates a port
func (s stack) rpcCreatePort(ctx context.Context, req ports.CreateOpts) (_ *ports.Port, ferr fail.Error) {
	var port *ports.Port

	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			aport, innerErr := ports.Create(s.NetworkClient, req).Extract()
			if innerErr != nil {
				return innerErr
			}

			port = aport
			return nil
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	return port, nil
}

// rpcCreatePort creates a port
func (s stack) rpcCreateUnsafePort(ctx context.Context, req ports.CreateOpts) (_ *ports.Port, ferr fail.Error) {
	var port *ports.Port

	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			var portWithPortSecurityExtensions struct {
				ports.Port
				portsecurity.PortSecurityExt
			}

			iFalse := false
			createOpts := portsecurity.PortCreateOptsExt{
				CreateOptsBuilder:   req,
				PortSecurityEnabled: &iFalse,
			}

			innerErr := ports.Create(s.NetworkClient, createOpts).ExtractInto(&portWithPortSecurityExtensions)
			if innerErr != nil {
				return innerErr
			}

			port = &portWithPortSecurityExtensions.Port

			return nil
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	return port, nil
}

// rpcChangePortSecurity changes port security
func (s stack) rpcChangePortSecurity(ctx context.Context, portID string, state bool) (_ *ports.Port, ferr fail.Error) {
	var port *ports.Port

	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			var portWithPortSecurityExtensions struct {
				ports.Port
				portsecurity.PortSecurityExt
			}

			iFalse := state
			portUpdateOpts := ports.UpdateOpts{}
			updateOpts := portsecurity.PortUpdateOptsExt{
				UpdateOptsBuilder:   portUpdateOpts,
				PortSecurityEnabled: &iFalse,
			}

			innerErr := ports.Update(s.NetworkClient, portID, updateOpts).ExtractInto(&portWithPortSecurityExtensions)
			if innerErr != nil {
				return innerErr
			}

			port = &portWithPortSecurityExtensions.Port

			return nil
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	return port, nil
}

// rpcRemoveSGFromPort removes all SG from ports
func (s stack) rpcRemoveSGFromPort(ctx context.Context, portID string) (_ *ports.Port, ferr fail.Error) {
	var port *ports.Port

	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			var portWithPortSecurityExtensions struct {
				ports.Port
				portsecurity.PortSecurityExt
			}

			portUpdateOpts := ports.UpdateOpts{
				SecurityGroups: &[]string{},
			}
			updateOpts := portsecurity.PortUpdateOptsExt{
				UpdateOptsBuilder: portUpdateOpts,
			}

			innerErr := ports.Update(s.NetworkClient, portID, updateOpts).ExtractInto(&portWithPortSecurityExtensions)
			if innerErr != nil {
				return innerErr
			}

			port = &portWithPortSecurityExtensions.Port

			return nil
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	return port, nil
}

// rpcDeletePort deletes a port
func (s stack) rpcDeletePort(ctx context.Context, id string) fail.Error {
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	return stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			return ports.Delete(s.NetworkClient, id).ExtractErr()
		},
		NormalizeError,
	)
}

// rpcListPorts lists all ports available
func (s stack) rpcListPorts(ctx context.Context, options ports.ListOpts) ([]ports.Port, fail.Error) {
	var (
		allPages pagination.Page
	)
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			allPages, innerErr = ports.List(s.NetworkClient, options).AllPages()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	r, err := ports.ExtractPorts(allPages)
	if err != nil {
		return nil, NormalizeError(err)
	}
	return r, nil
}

// rpcUpdatePort updates the settings of a port
func (s stack) rpcUpdatePort(ctx context.Context, id string, options ports.UpdateOpts) fail.Error {
	if id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			resp, innerErr := ports.Update(s.NetworkClient, id, options).Extract()
			_ = resp
			return innerErr
		},
		NormalizeError,
	)
}

// rpcGetServer returns
func (s stack) rpcGetServer(ctx context.Context, id string) (_ *servers.Server, ferr fail.Error) {
	if id == "" {
		return &servers.Server{}, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	var resp *servers.Server
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = servers.Get(s.ComputeClient, id).Extract()
			return err
		},
		NormalizeError,
	)
	if xerr != nil {
		return &servers.Server{}, xerr
	}
	return resp, nil
}

// rpcGetPort returns port information from its ID
func (s stack) rpcGetPort(ctx context.Context, id string) (port *ports.Port, ferr fail.Error) {
	if id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	xerr := stacks.RetryableRemoteCall(ctx,
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
func (s stack) rpcCreateFloatingIP(ctx context.Context) (*floatingips.FloatingIP, fail.Error) {
	var resp *floatingips.FloatingIP
	xerr := stacks.RetryableRemoteCall(ctx,
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
func (s stack) rpcDeleteFloatingIP(ctx context.Context, id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return floatingips.Delete(s.ComputeClient, id).ExtractErr()
		},
		NormalizeError,
	)
}

func (s stack) rpcGetFloatingIP(ctx context.Context, id string) (interface{}, fail.Error) {
	panic("not implemented")
}
