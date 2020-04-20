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
	var srcErr error

	srcErr = gophercloud.ErrDefault409{}
	code, err := GetUnexpectedGophercloudErrorCode(srcErr)
	if err != nil {
		t.FailNow()
	}
	if code != 0 {
		t.FailNow()
	}
}

func TestNotGophercloudErrorCodes(t *testing.T) {
	var srcErr error

	srcErr = fmt.Errorf("something else")
	code, err := GetUnexpectedGophercloudErrorCode(srcErr)
	if err == nil {
		t.FailNow()
	}
	if code != 0 {
		t.FailNow()
	}
}
