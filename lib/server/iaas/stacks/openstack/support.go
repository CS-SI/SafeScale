package openstack

import (
	"fmt"
	"reflect"
)

func GetUnexpectedGophercloudErrorCode(err error) (int64, error) {
	xType := reflect.TypeOf(err)
	xValue := reflect.ValueOf(err)

	_, there := xType.FieldByName("ErrUnexpectedResponseCode")
	if there {
		_, there := xType.FieldByName("Actual")
		if there {
			return xValue.FieldByName("Actual").Int(), nil
		}
	}

	return 0, fmt.Errorf("not a gophercloud.ErrUnexpectedResponseCode")
}
