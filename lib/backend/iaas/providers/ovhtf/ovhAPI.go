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

package ovhtf

import (
	"context"
	"fmt"
	"reflect"

	"github.com/ovh/go-ovh/ovh"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// OVHAPI contains specific authentication options for OVH native API
type OVHAPI struct {
	ApplicationKey    string
	ApplicationSecret string
	ConsumerKey       string
}

func (p *provider) requestOVHAPI(_ context.Context, url string, httpCode string) (interface{}, fail.Error) {
	authOpts, xerr := p.AuthenticationOptions()
	if xerr != nil {
		return nil, xerr
	}

	ovhAPI, ok := authOpts.Specific.(OVHAPI)
	if !ok {
		return nil, fail.InvalidRequestError("missing 'OVHAPI' in 'AuthenticationOptions.Specific' field (found '%s' instead)", reflect.TypeOf(authOpts.Specific).String())
	}
	alternateAPIApplicationKey := ovhAPI.ApplicationKey
	if alternateAPIApplicationKey == "" {
		return nil, fail.SyntaxError("Specific.ApplicationKey is not set (mandatory to access native OVH API)")
	}
	alternateAPIApplicationSecret := ovhAPI.ApplicationSecret
	if alternateAPIApplicationSecret == "" {
		return nil, fail.SyntaxError("Specific.ApplicationSecret is not set (mandatory to access native OVH API)")
	}
	alternateAPIConsumerKey := ovhAPI.ConsumerKey
	if alternateAPIConsumerKey == "" {
		return nil, fail.SyntaxError("Specific.ConsumerKey is not set (mandatory to access native OVH API)")
	}

	client, err := ovh.NewClient(
		"ovh-eu",
		alternateAPIApplicationKey,
		alternateAPIApplicationSecret,
		alternateAPIConsumerKey,
	)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	var result interface{}
	switch httpCode {
	case "GET":
		if err := client.Get(url, &result); err != nil {
			return nil, fail.Wrap(err)
		}
	case "PUT":
		return nil, fail.NotImplementedError(fmt.Sprintf("%s not implemented yet", httpCode)) // FIXME: Technical debt
	case "POST":
		return nil, fail.NotImplementedError(fmt.Sprintf("%s not implemented yet", httpCode)) // FIXME: Technical debt
	case "DELETE":
		return nil, fail.NotImplementedError(fmt.Sprintf("%s not implemented yet", httpCode)) // FIXME: Technical debt
	default:
		return nil, fail.NewError("unexpected HTTP code: %s", httpCode)
	}

	return result, nil
}
