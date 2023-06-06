package enums

import "github.com/CS-SI/SafeScale/v22/lib/utils/fail"

type Client int

const (
	OVH Client = iota
	AWS
	Cloudferro
	_
	FlexibleEngine
	GCP
	_
	OpenStack
	Outscale
	_
	Azure
)

var (
	clientStringMap = map[string]Client{
		"ovh":            OVH,
		"aws":            AWS,
		"cloudferro":     Cloudferro,
		"flexibleengine": FlexibleEngine,
		"gcp":            GCP,
		"openstack":      OpenStack,
		"outscale":       Outscale,
		"azuretf":        Azure,
	}

	clientEnumMap = map[Client]string{
		OVH:            "OVH",
		AWS:            "AWS",
		Cloudferro:     "Cloudferro",
		FlexibleEngine: "FlexibleEngine",
		GCP:            "GCP",
		OpenStack:      "OpenStack",
		Outscale:       "Outscale",
		Azure:          "Azure",
	}
)

func ParseClient(s string) (Client, error) {
	var (
		p  Client
		ok bool
	)
	if p, ok = clientStringMap[s]; !ok {
		return p, fail.NotFoundError("failed to find a Provider matching with '%s'", s)
	}
	return p, nil
}

func (p Client) String() string {
	if s, ok := clientEnumMap[p]; ok {
		return s
	}
	return ""
}
