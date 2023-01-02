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

package openstack

import (
	"fmt"
	"testing"

	"github.com/gophercloud/gophercloud"
)

func TestGophercloudErrorCodes(t *testing.T) {

	srcErr := gophercloud.ErrDefault409{
		ErrUnexpectedResponseCode: gophercloud.ErrUnexpectedResponseCode{
			BaseError: gophercloud.BaseError{},
			URL:       "",
			Method:    "",
			Expected:  nil,
			Actual:    409,
			Body:      nil,
		},
	}

	code, err := GetUnexpectedGophercloudErrorCode(srcErr)
	if err != nil {
		t.FailNow()
	}
	if code != 409 {
		t.FailNow()
	}
}

func TestEmptyGophercloudErrorCodes(t *testing.T) {
	srcErr := gophercloud.ErrDefault409{}
	code, err := GetUnexpectedGophercloudErrorCode(srcErr)
	if err == nil {
		t.Errorf("Received: %v", err)
		t.FailNow()
	}
	if code != 0 {
		t.Errorf("The code was: %d", code)
		t.FailNow()
	}
}

func TestNotGophercloudErrorCodes(t *testing.T) {
	srcErr := fmt.Errorf("something else")
	code, err := GetUnexpectedGophercloudErrorCode(srcErr)
	if err == nil {
		t.FailNow()
	}
	if code != 0 {
		t.FailNow()
	}
}
