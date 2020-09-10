package openstack

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

func caseInsensitiveContains(haystack, needle string) bool {
	lowerHaystack := strings.ToLower(haystack)
	lowerNeedle := strings.ToLower(needle)

	return strings.Contains(lowerHaystack, lowerNeedle)
}

func IsServiceUnavailableError(err error) bool {
	if err != nil {
		text := err.Error()
		return caseInsensitiveContains(text, "Service Unavailable")
	}

	return false
}

func GetUnexpectedGophercloudErrorCode(err error) (int64, error) {
	xType := reflect.TypeOf(err)
	xValue := reflect.ValueOf(err)

	if xValue.Kind() != reflect.Struct {
		return 0, scerr.Errorf(fmt.Sprintf("not a gophercloud.ErrUnexpectedResponseCode"), nil)
	}

	_, there := xType.FieldByName("ErrUnexpectedResponseCode")
	if there {
		_, there := xType.FieldByName("Actual")
		if there {
			recoveredValue := xValue.FieldByName("Actual").Int()
			if recoveredValue != 0 {
				return recoveredValue, nil
			}
		}
	}

	return 0, scerr.Errorf(fmt.Sprintf("not a gophercloud.ErrUnexpectedResponseCode"), nil)
}

func ReinterpretGophercloudErrorCode(gopherErr error, success []int64, transparent []int64, abort []int64, defaultHandler func(error) error) error {
	if gopherErr == nil {
		return gopherErr
	}

	if code, err := GetUnexpectedGophercloudErrorCode(gopherErr); code != 0 && err == nil {
		for _, tcode := range success {
			if tcode == code {
				return nil
			}
		}

		for _, tcode := range abort {
			if tcode == code {
				return scerr.AbortedError("", gopherErr)
			}
		}

		for _, tcode := range transparent {
			if tcode == code {
				return gopherErr
			}
		}

		if defaultHandler == nil {
			return nil
		}

		return defaultHandler(gopherErr)
	}

	return gopherErr
}

func defaultErrorInterpreter(inErr error) error {
	return ReinterpretGophercloudErrorCode(
		inErr, nil, []int64{408, 409, 425, 429, 500, 503, 504}, nil, func(ferr error) error {
			if IsServiceUnavailableError(ferr) {
				return ferr
			}

			return scerr.AbortedError("", ferr)
		},
	)
}
