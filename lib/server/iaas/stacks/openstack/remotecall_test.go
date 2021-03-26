package openstack

import (
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/gophercloud/gophercloud"
)

// NOTE, Testing this with enviroment variable SAFESCALE_COMMUNICATION_TIMEOUT=5s is STRONGLY advised

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
		Err: fmt.Errorf("Horrible things happened"),
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
