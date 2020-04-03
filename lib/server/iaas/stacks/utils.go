package stacks

import (
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
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
			return nil, "", scerr.InvalidParameterError("hostParam", "cannot be empty string")
		}
		ahc = abstract.NewHostCore()
		ahc.ID = hostParam
		hostRef = hostParam
	case *abstract.HostCore:
		if hostParam == nil {
			return nil, "", scerr.InvalidParameterError("hostParam", "canot be nil")
		}
		ahc = hostParam
		hostRef = ahc.Name
		if hostRef == "" {
			hostRef = ahc.ID
		}
		if hostRef == "" {
			return nil, "", scerr.InvalidParameterError("hostParam", "at least one of fields 'ID' or 'Name' must not be empty string")
		}
	default:
		return nil, "", scerr.InvalidParameterError("hostParam", "must be a non-empty string or a *abstract.HostCore")
	}
	return ahc, hostRef, nil
}
