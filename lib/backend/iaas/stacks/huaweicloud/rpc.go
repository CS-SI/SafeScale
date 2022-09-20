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
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
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

// rpcListPorts lists all ports available
func (s stack) rpcListPorts(ctx context.Context, options ports.ListOpts) ([]ports.Port, fail.Error) {
	var (
		emptyList []ports.Port
		allPages  pagination.Page
	)
	xerr := stacks.RetryableRemoteCall(ctx,
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
