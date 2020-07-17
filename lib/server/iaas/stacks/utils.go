package stacks

import (
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// HostParameter can represent a host by a string (containing name or id), an *abstract.HostCore or an *abstract.HostFull
type HostParameter interface{}

// ValidateHostParameter validates host parameter that can be a string as ID or an *abstract.HostCore
func ValidateHostParameter(hostParam HostParameter) (ahf *abstract.HostFull, hostRef string, xerr fail.Error) {
	ahf = abstract.NewHostFull()
	switch hostParam := hostParam.(type) {
	case string:
		if hostParam == "" {
			return nil, "", fail.InvalidParameterError("hostParam", "cannot be empty string")
		}
		ahf.Core.ID = hostParam
		hostRef = hostParam
	case *abstract.HostCore:
		if hostParam.IsNull() {
			return nil, "", fail.InvalidParameterError("hostParam", "cannot be *abstract.HostCore null value")
		}
		ahf.Core = hostParam
		hostRef = ahf.Core.Name
		if hostRef == "" {
			hostRef = ahf.Core.ID
		}
	case *abstract.HostFull:
		if hostParam.IsNull() {
			return nil, "", fail.InvalidParameterError("hostParam", "cannot be *abstract.HostFull null value")
		}
		ahf = hostParam
		hostRef = ahf.Core.Name
		if hostRef == "" {
			hostRef = ahf.Core.ID
		}
	default:
		return nil, "", fail.InvalidParameterError("hostParam", "valid types are non-empty string, *abstract.HostCore or *abstract.HostFull")
	}
	if hostRef == "" {
		return nil, "", fail.InvalidParameterError("hostParam", "at least one of fields 'ID' or 'Name' must not be empty string")
	}
	if ahf.Core.ID == "" {
		return nil, "", fail.InvalidParameterError("hostParam", "field ID cannot be empty string")
	}
	return ahf, hostRef, nil
}
