/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/antihax/optional"
	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

func (s stack) getResourceTags(id string) (map[string]string, fail.Error) {
	tags := make(map[string]string)
	readTagsOpts := osc.ReadTagsOpts{
		ReadTagsRequest: optional.NewInterface(osc.ReadTagsRequest{
			Filters: osc.FiltersTag{ResourceIds: []string{id}},
		}),
	}
	var resp osc.ReadTagsResponse
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.TagApi.ReadTags(s.auth, &readTagsOpts)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return tags, xerr
	}
	for _, tag := range resp.Tags {
		tags[tag.Key] = tag.Value
	}
	return tags, nil
}

func getResourceTag(tags []osc.ResourceTag, key, defaultValue string) string {
	for _, tag := range tags {
		if tag.Key == key {
			return tag.Value
		}
	}
	return defaultValue
}

func (s stack) setResourceTags(id string, tags map[string]string) ([]osc.ResourceTag, fail.Error) {
	var tagList []osc.ResourceTag
	for k, v := range tags {
		tagList = append(tagList, osc.ResourceTag{
			Key:   k,
			Value: v,
		})
	}
	createTagsOpts := osc.CreateTagsOpts{
		CreateTagsRequest: optional.NewInterface(osc.CreateTagsRequest{
			ResourceIds: []string{id},
			Tags:        tagList,
		}),
	}
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, _, innerErr := s.client.TagApi.CreateTags(s.auth, &createTagsOpts)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	return tagList, xerr
}

func unwrapTags(tags []osc.ResourceTag) map[string]string {
	m := make(map[string]string)
	for _, tag := range tags {
		m[tag.Key] = tag.Value
	}
	return m
}
