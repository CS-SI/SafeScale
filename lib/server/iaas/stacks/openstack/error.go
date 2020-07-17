package openstack

import (
    "encoding/json"
    "fmt"
    "reflect"
    "strings"

    "github.com/sirupsen/logrus"

    "github.com/gophercloud/gophercloud"

    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ProviderErrorToString creates an error string from openstack api error
func ProviderErrorToString(err error) string {
    if err == nil {
        return ""
    }
    switch e := err.(type) {
    case gophercloud.ErrDefault401:
        return fmt.Sprintf("code: 401, reason: %s", string(e.Body))
    case *gophercloud.ErrDefault401:
        return fmt.Sprintf("code: 401, reason: %s", string(e.Body))
    case gophercloud.ErrDefault404:
        return fmt.Sprintf("code: 404, reason: %s", string(e.Body))
    case *gophercloud.ErrDefault404:
        return fmt.Sprintf("code: 404, reason: %s", string(e.Body))
    case gophercloud.ErrDefault409:
        return fmt.Sprintf("code: 409, reason: %s", string(e.Body))
    case *gophercloud.ErrDefault409:
        return fmt.Sprintf("code: 409, reason: %s", string(e.Body))
    case gophercloud.ErrDefault500:
        return fmt.Sprintf("code: 500, reason: %s", string(e.Body))
    case *gophercloud.ErrDefault500:
        return fmt.Sprintf("code: 500, reason: %s", string(e.Body))
    case gophercloud.ErrUnexpectedResponseCode:
        return fmt.Sprintf("code: %d, reason: %s", e.Actual, string(e.Body))
    case *gophercloud.ErrUnexpectedResponseCode:
        return fmt.Sprintf("code: %d, reason: %s", e.Actual, string(e.Body))
    default:
        logrus.Debugf("Error code not yet handled specifically: ProviderErrorToString(%s, %+v)\n", reflect.TypeOf(err).String(), err)
        return err.Error()
    }
}

// NormalizeError translates gophercloud or openstack error to SafeScale error
func NormalizeError(err error) fail.Error {
    if err == nil {
        return nil
    }
    switch e := err.(type) {
    case gophercloud.ErrDefault401:
        return fail.NotAuthenticatedError(string(e.Body))
    case *gophercloud.ErrDefault401:
        return fail.NotAuthenticatedError(string(e.Body))
    case gophercloud.ErrDefault403:
        return fail.ForbiddenError(string(e.Body))
    case *gophercloud.ErrDefault403:
        return fail.ForbiddenError(string(e.Body))
    case gophercloud.ErrDefault404:
        return fail.NotFoundError(string(e.Body))
    case *gophercloud.ErrDefault404:
        return fail.NotFoundError(string(e.Body))
    case gophercloud.ErrDefault429:
        return fail.OverloadError(string(e.Body))
    case *gophercloud.ErrDefault429:
        return fail.OverloadError(string(e.Body))
    case gophercloud.ErrDefault500:
        return fail.InvalidRequestError(string(e.Body))
    case *gophercloud.ErrDefault500:
        return fail.InvalidRequestError(string(e.Body))
    case gophercloud.ErrUnexpectedResponseCode:
        return fail.NewError("unexpected response code: code: %d, reason: %s", e.Actual, string(e.Body))
    case *gophercloud.ErrUnexpectedResponseCode:
        return fail.NewError("unexpected response code: code: %d, reason: %s", e.Actual, string(e.Body))
    default:
        logrus.Debugf("Unhandled error (%s) received from provider: %s", reflect.TypeOf(err).String(), err.Error())
        return fail.NewError("unhandled error received from provider: %s", err.Error())
    }
}

// ParseNeutronError parses neutron json error and returns fields
// Returns (nil, fail.ErrSyntax) if json syntax error occured (and maybe operation should be retried...)
// Returns (nil, fail.Error) if any other error occurs
// Returns (<retval>, nil) if everything is understood
func ParseNeutronError(neutronError string) (map[string]string, fail.Error) {
    startIdx := strings.Index(neutronError, "{\"NeutronError\":")
    jsonError := strings.Trim(neutronError[startIdx:], " ")
    unjsoned := map[string]map[string]interface{}{}
    if err := json.Unmarshal([]byte(jsonError), &unjsoned); err != nil {
        switch err.(type) {
        case *json.SyntaxError:
            return nil, fail.SyntaxError(err.Error())
        default:
            logrus.Debugf(err.Error())
            return nil, fail.ToError(err)
        }
    }
    if content, ok := unjsoned["NeutronError"]; ok {
        retval := map[string]string{
            "message": "",
            "type":    "",
            "code":    "",
            "detail":  "",
        }
        if field, ok := content["message"].(string); ok {
            retval["message"] = field
        }
        if field, ok := content["type"].(string); ok {
            retval["type"] = field
        }
        if field, ok := content["code"].(string); ok {
            retval["code"] = field
        }
        if field, ok := content["detail"].(string); ok {
            retval["detail"] = field
        }

        return retval, nil
    }
    return nil, nil
}
