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
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"strings"

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
