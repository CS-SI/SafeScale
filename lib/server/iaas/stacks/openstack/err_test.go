package openstack

import (
	"github.com/gophercloud/gophercloud"
	"testing"
)

func TestGophercloudErrorCodes(t *testing.T) {

	var srcErr error
	srcErr = gophercloud.ErrDefault409{
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
