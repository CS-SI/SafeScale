package openstack

import (
	"testing"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/gophercloud/gophercloud"
)

var numCalls int

func gen503Err() error {
	numCalls++
	return gophercloud.ErrDefault503{
		gophercloud.ErrUnexpectedResponseCode{
			BaseError: gophercloud.BaseError{},
			URL:       "",
			Method:    "",
			Expected:  []int{200},
			Actual:    503,
			Body:      []byte("Shit happens"),
		},
	}
}

func TestRetryableRemoteCall(t *testing.T) {
	theErr := stacks.RetryableRemoteCall(gen503Err, NormalizeError)
	if numCalls <= 1 {
		t.Errorf("No retries at all")
		t.FailNow()
	}
	if theErr != nil {
		t.Errorf("It should have failed")
		t.FailNow()
	}
}
