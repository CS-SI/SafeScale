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

package ovh

import (
	"fmt"

	"github.com/ovh/go-ovh/ovh"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

func (p *provider) requestOVHAPI(url string, httpCode string) (interface{}, fail.Error) {
	authOpts, xerr := p.GetAuthenticationOptions()
	if xerr != nil {
		return nil, xerr
	}

	alternateAPIApplicationKey := authOpts.GetString("AlternateApiApplicationKey")
	if alternateAPIApplicationKey == "" {
		return nil, fail.SyntaxError("AlternateApiApplicationKey is not set (mandatory to access native OVH API)")
	}
	alternateAPIApplicationSecret := authOpts.GetString("AlternateApiApplicationSecret")
	if alternateAPIApplicationSecret == "" {
		return nil, fail.SyntaxError("AlternateApiApplicationSecret is not set (mandatory to access native OVH API)")
	}
	alternateAPIConsumerKey := authOpts.GetString("AlternateApiConsumerKey")
	if alternateAPIConsumerKey == "" {
		return nil, fail.SyntaxError("AlternateApiConsumerKey is not set (mandatory to access native OVH API)")
	}

	client, err := ovh.NewClient(
		"ovh-eu",
		alternateAPIApplicationKey,
		alternateAPIApplicationSecret,
		alternateAPIConsumerKey,
	)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	var result interface{}
	switch httpCode {
	case "GET":
		if err := client.Get(url, &result); err != nil {
			return nil, fail.ConvertError(err)
		}
	case "PUT":
		return nil, fail.NotImplementedError(fmt.Sprintf("%s not implemented yet", httpCode))
	case "POST":
		return nil, fail.NotImplementedError(fmt.Sprintf("%s not implemented yet", httpCode))
	case "DELETE":
		return nil, fail.NotImplementedError(fmt.Sprintf("%s not implemented yet", httpCode))
	default:
		return nil, fail.NewError("unexpected HTTP code: %s", httpCode)
	}

	return result, nil
}
