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

package converters

import (
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

func IndexedListOfClusterNodesFromResourceToProtocol(in resources.IndexedListOfClusterNodes) (*protocol.ClusterNodeListResponse, fail.Error) {
	out := &protocol.ClusterNodeListResponse{}
	if len(in) == 0 {
		return out, nil
	}
	out.Nodes = make([]*protocol.Host, 0, len(in))
	for _, v := range in {
		item := &protocol.Host{
			Id:   v.ID,
			Name: v.Name,
		}
		out.Nodes = append(out.Nodes, item)
	}
	return out, nil
}

func FeatureSliceFromResourceToProtocol(in []resources.Feature) *protocol.FeatureListResponse {
	out := &protocol.FeatureListResponse{}
	out.Features = make([]*protocol.FeatureResponse, 0, len(in))
	for _, v := range in {
		out.Features = append(out.Features, v.ToProtocol())
	}
	return out
}
