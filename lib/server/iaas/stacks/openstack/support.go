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
    text := err.Error()

    return caseInsensitiveContains(text, "Service Unavailable")
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
