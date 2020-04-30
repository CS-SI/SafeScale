package stacks

import (
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ValidateHostParam validates host parameter that can be a string as ID or an *abstract.HostCore
func ValidateHostParam(hostParam interface{}) (*abstract.HostCore, string, error) {
	var (
		ahc     *abstract.HostCore
		hostRef string
	)
	switch hostParam := hostParam.(type) {
	case string:
		if hostParam == "" {
			return nil, "", fail.InvalidParameterReport("hostParam", "cannot be empty string")
		}
		ahc = abstract.NewHostCore()
		ahc.ID = hostParam
		hostRef = hostParam
	case *abstract.HostCore:
		if hostParam == nil {
			return nil, "", fail.InvalidParameterReport("hostParam", "canot be nil")
		}
		ahc = hostParam
		hostRef = ahc.Name
		if hostRef == "" {
			hostRef = ahc.ID
		}
		if hostRef == "" {
			return nil, "", fail.InvalidParameterReport("hostParam", "at least one of fields 'ID' or 'Name' must not be empty string")
		}
	default:
		return nil, "", fail.InvalidParameterReport("hostParam", "must be a non-empty string or a *abstract.HostCore")
	}
	return ahc, hostRef, nil
}
