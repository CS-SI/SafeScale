/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or provideried.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ovh

import (
	"fmt"

	"github.com/ovh/go-ovh/ovh"
)

func (p *provider) requestOVHAPI(url string, httpCode string) (interface{}, error) {
	authOpts, err := p.GetAuthOpts()
	if err != nil {
		return nil, err
	}

	alternateAPIApplicationKey := authOpts.GetString("AlternateApiConsumerKey")
	if alternateAPIApplicationKey == "" {
		return nil, fmt.Errorf("AlternateAPIApplicationKey is left unset while mandatory to access OVH-API")
	}
	alternateAPIApplicationSecret := authOpts.GetString("AlternateApiApplicationSecret")
	if alternateAPIApplicationSecret == "" {
		return nil, fmt.Errorf("AlternateAPIApplicationSecret is left unset while mandatory to access OVH-API")
	}
	alternateAPIConsumerKey := authOpts.GetString("AlternateApiConsumerKey")
	if alternateAPIConsumerKey == "" {
		return nil, fmt.Errorf("AlternateAPIConsumerKey is left unset while mandatory to access OVH-API")
	}

	client, err := ovh.NewClient(
		"ovh-eu",
		alternateAPIApplicationKey,
		alternateAPIApplicationSecret,
		alternateAPIConsumerKey,
	)
	if err != nil {
		return nil, err
	}

	var result interface{}
	switch httpCode {
	case "GET":
		if err := client.Get(url, &result); err != nil {
			return nil, err
		}
	case "PUT":
		return nil, fmt.Errorf("%s not implemented yet", httpCode)
	case "POST":
		return nil, fmt.Errorf("%s not implemented yet", httpCode)
	case "DELETE":
		return nil, fmt.Errorf("%s not implemented yet", httpCode)
	default:
		return nil, fmt.Errorf("Unexpected HTTP code : %s", httpCode)
	}

	return result, nil
}
