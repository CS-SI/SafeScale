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
	"github.com/antihax/optional"
	"github.com/outscale-dev/osc-sdk-go/osc"
)

func (s *Stack) getResourceTags(id string) (map[string]string, error) {
	readTagsRequest := osc.ReadTagsRequest{
		Filters: osc.FiltersTag{ResourceIds: []string{id}},
	}
	resp, _, err := s.client.TagApi.ReadTags(
		s.auth, &osc.ReadTagsOpts{
			ReadTagsRequest: optional.NewInterface(readTagsRequest),
		},
	)
	tags := make(map[string]string)
	if err != nil {
		return tags, normalizeError(err)
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

func (s *Stack) setResourceTags(id string, tags map[string]string) error {
	var tagList []osc.ResourceTag
	for k, v := range tags {
		tagList = append(
			tagList, osc.ResourceTag{
				Key:   k,
				Value: v,
			},
		)
	}
	createTagsRequest := osc.CreateTagsRequest{
		ResourceIds: []string{id},
		Tags:        tagList,
	}
	_, _, err := s.client.TagApi.CreateTags(
		s.auth, &osc.CreateTagsOpts{
			CreateTagsRequest: optional.NewInterface(createTagsRequest),
		},
	)
	return normalizeError(err)
}

func unwrapTags(tags []osc.ResourceTag) map[string]string {
	m := make(map[string]string)
	for _, tag := range tags {
		m[tag.Key] = tag.Value
	}
	return m
}
