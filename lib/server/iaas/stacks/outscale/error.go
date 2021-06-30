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

package outscale

import (
	"encoding/json"
	"reflect"

	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

func normalizeError(err error) fail.Error {
	if err == nil {
		return nil
	}

	switch realErr := err.(type) {
	case osc.GenericOpenAPIError:
		switch model := realErr.Model().(type) {
		case osc.ErrorResponse:
			if len(model.Errors) > 0 {
				merr := model.Errors[0]
				if out := qualifyFromCode(merr.Code, merr.Details); out != nil {
					return out
				}

				reqID := model.ResponseContext.RequestId
				return fail.UnknownError("from outscale driver, code='%s', type='%s', details='%s', requestId='%s'", merr.Code, merr.Type, merr.Details, reqID)
			}
			if out := qualifyFromBody(realErr.Body()); out != nil {
				return out
			}
			return fail.UnknownError("from outscale driver, type='%s', error='%s'", reflect.TypeOf(realErr), realErr.Error())
		default:
			if out := qualifyFromBody(realErr.Body()); out != nil {
				return out
			}
			return fail.UnknownError("from outscale driver, type='%s', error='%s'", reflect.TypeOf(realErr), realErr.Error())
		}
	default:
		return fail.ConvertError(err)
	}
}

func qualifyFromCode(code, details string) fail.Error {
	switch code {
	case "1":
		return fail.NotAuthenticatedError("user is not authenticated")
	case "4019":
		return fail.InvalidRequestError("invalid device name")
	case "4045":
		return fail.InvalidRequestError("invalid Targets")
	case "4047":
		if details == "" {
			details = "invalid parameter"
		}
		return fail.InvalidRequestError(details)
	case "5009":
		return fail.NotFoundError("availability zone not found")
	case "5020":
		return fail.NotFoundError("security group not found")
	case "5057":
		return fail.NotFoundError("subnet not found")
	case "5063":
		return fail.NotFoundError("host not found")
	case "5065":
		return fail.NotFoundError("network not found")
	case "5071":
		return fail.NotFoundError("keypair not found")
	case "9005":
		return fail.InvalidRequestError("an equivalent rule exist for the same CIDR")
	case "9008":
		return fail.DuplicateError("a Security Group with this name already exists")
	case "9011":
		return fail.DuplicateError("a keypair with this name already exists")
	case "9029": // this means the network has associated resources still in use, we have to delete those first
		return fail.InvalidRequestError("the network is still in use")
	case "9044":
		return fail.InvalidRequestError("not included in VPC Targets")
	case "9058":
		return fail.DuplicateError("network already exist")
	case "10010":
		return fail.OverloadError("host quota exceeded")
	case "10022":
		return fail.OverloadError("network/VPC quota exceeded")
	case "10023":
		return fail.OverloadError("internet gateway quota exceeded")
	case "10029":
		return fail.OverloadError("cpu core quota exceeded")
	case "10042":
		return fail.OverloadError("memory quota exceeded")
	}
	return nil
}

func qualifyFromBody(in []byte) fail.Error {
	var jsoned map[string]interface{}
	if err := json.Unmarshal(in, &jsoned); err != nil {
		return fail.ConvertError(err)
	}
	if errs, ok := jsoned["Errors"].([]interface{}); ok {
		for _, v := range errs {
			item := v.(map[string]interface{})
			var details string
			if details, ok = item["Details"].(string); !ok {
				details = ""
			}
			if code, ok := item["Code"].(string); ok {
				if out := qualifyFromCode(code, details); out != nil {
					return out
				}
			}
		}
	}
	return nil
}
