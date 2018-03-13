package IPVersion

import (
	"net"
	"strings"
)

//go:generate stringer -type=Enum

//Enum is an enum defining IP versions
type Enum int

const (
	//IPv4 is IP v4 version
	IPv4 Enum = 4
	//IPv6 is IP v6 version
	IPv6 Enum = 6
)

//Is checks the version of a IP address in string representaiton
func (version Enum) Is(str string) bool {
	ip := net.ParseIP(str)
	isV6 := ip != nil && strings.Contains(str, ":")
	switch version {
	case IPv4:
		return !isV6
	case IPv6:
		return isV6
	default:
		return false
	}
}
