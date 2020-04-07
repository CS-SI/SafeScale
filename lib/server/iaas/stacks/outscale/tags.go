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

import "github.com/outscale/osc-sdk-go/oapi"

func (s *Stack) getResourceTags(id string) (map[string]string, error) {
	resp, err := s.client.POST_ReadTags(oapi.ReadTagsRequest{
		Filters: oapi.FiltersTag{ResourceIds: []string{id}},
	})
	tags := make(map[string]string)
	if err != nil {
		return tags, err
	}
	for _, tag := range resp.OK.Tags {
		tags[tag.Key] = tag.Value
	}
	return tags, nil
}

func getResourceTag(tags []oapi.ResourceTag, key, defaultValue string) string {
	for _, tag := range tags {
		if tag.Key == key {
			return tag.Value
		}
	}
	return defaultValue
}

func (s *Stack) setResourceTags(id string, tags map[string]string) error {
	var tlist []oapi.ResourceTag
	for k, v := range tags {
		tlist = append(tlist, oapi.ResourceTag{
			Key:   k,
			Value: v,
		})
	}
	_, err := s.client.POST_CreateTags(oapi.CreateTagsRequest{
		ResourceIds: []string{id},
		Tags:        tlist,
	})
	return err
}

func unwrapTags(tags []oapi.ResourceTag) map[string]string {
	m := make(map[string]string)
	for _, tag := range tags {
		m[tag.Key] = tag.Value
	}
	return m
}
