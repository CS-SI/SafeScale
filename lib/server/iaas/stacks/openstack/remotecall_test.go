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

package openstack

import (
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/stacks"
	"github.com/gophercloud/gophercloud"
)

// NOTE, Testing this with environment variable SAFESCALE_COMMUNICATION_TIMEOUT=5s is STRONGLY advised

var numCalls int
var numDNSCalls int
var numBadURLs int
var numNotThere int

func gen404Err() error {
	numNotThere++
	return gophercloud.ErrDefault404{
		ErrUnexpectedResponseCode: gophercloud.ErrUnexpectedResponseCode{
			BaseError: gophercloud.BaseError{},
			URL:       "",
			Method:    "",
			Expected:  []int{200},
			Actual:    404,
			Body:      []byte("looking for something ?"),
		},
	}
}

func gen503Err() error {
	numCalls++
	return gophercloud.ErrDefault503{
		ErrUnexpectedResponseCode: gophercloud.ErrUnexpectedResponseCode{
			BaseError: gophercloud.BaseError{},
			URL:       "",
			Method:    "",
			Expected:  []int{200},
			Actual:    503,
			Body:      []byte("something bad happened"),
		},
	}
}

func genDNSError() error {
	numDNSCalls++
	return &net.DNSError{
		Err:         "failure",
		Name:        "failure's name",
		Server:      "ourserver.com",
		IsTimeout:   false,
		IsTemporary: false,
		IsNotFound:  false,
	}
}

func genNetURLError() error {
	numBadURLs++
	return &url.Error{
		Op:  "GET",
		URL: "http://whocares.com",
		Err: fmt.Errorf("horrible things happened"),
	}
}

func TestDropRetriesIfNotFound(t *testing.T) {
	theErr := stacks.RetryableRemoteCall(gen404Err, NormalizeError)
	if numNotThere > 1 {
		t.Errorf("We should have stop trying")
		t.FailNow()
	}
	if theErr == nil {
		t.Errorf("It should have failed")
		t.FailNow()
	}
}

func TestRetryableURLError(t *testing.T) {
	theErr := stacks.RetryableRemoteCall(genNetURLError, NormalizeError)
	if numBadURLs <= 1 {
		t.Errorf("No retries at all")
		t.FailNow()
	}
	if theErr == nil {
		t.Errorf("It should have failed")
		t.FailNow()
	}
}

func TestRetryableNetError(t *testing.T) {
	theErr := stacks.RetryableRemoteCall(genDNSError, NormalizeError)
	if numDNSCalls <= 1 {
		t.Errorf("No retries at all")
		t.FailNow()
	}
	if theErr == nil {
		t.Errorf("It should have failed")
		t.FailNow()
	}
}

func TestRetryableRemoteCall(t *testing.T) {
	theErr := stacks.RetryableRemoteCall(gen503Err, NormalizeError)
	if numCalls <= 1 {
		t.Errorf("No retries at all")
		t.FailNow()
	}
	if theErr == nil {
		t.Errorf("It should have failed")
		t.FailNow()
	}
}
