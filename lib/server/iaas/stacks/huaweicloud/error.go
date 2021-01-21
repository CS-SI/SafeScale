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

package huaweicloud

import (
	"encoding/json"
	"fmt"

	"github.com/gophercloud/gophercloud"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// normalizeError translates gophercloud or openstack error to SafeScale error
func normalizeError(err error) fail.Error {
	if err == nil {
		return nil
	}

	switch lvl1 := err.(type) {
	case fail.Error:
		if cause := lvl1.Cause(); cause != nil {
			switch lvl2 := cause.(type) {
			case gophercloud.ErrDefault400:
				return openstack.NormalizeError(reduceHuaweicloudError(lvl2.Body))
			}
		}
	}
	return openstack.NormalizeError(err)
}

// reduceHuaweicloudError ...
func reduceHuaweicloudError(in []byte) (xerr fail.Error) {
	// FIXME: check if json.Unmarshal() may panic; if not theses 2 defers are superfluous
	defer func() {
		switch xerr.(type) {
		case *fail.ErrRuntimePanic:
			xerr = fail.InvalidRequestError(string(in))
		}
	}()
	defer fail.OnPanic(&xerr)

	var body map[string]interface{}
	unjsonedErr := json.Unmarshal(in, &body)
	if unjsonedErr == nil {
		if code, ok := body["code"].(string); ok {
			switch code {
			case "VPC.0101":
				return fail.NotFoundError("failed to find VPC")
			case "VPC.0209":
				return fail.NotAvailableError("subnet still in use")
			}
		}
	}

	logrus.Debugf(callstack.DecorateWith("", "", fmt.Sprintf("Unhandled error received from provider: %s", string(in)), 0))
	return fail.NewError("unhandled error received from provider: %s", string(in))
}
