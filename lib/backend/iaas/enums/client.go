package enums

import "github.com/CS-SI/SafeScale/v22/lib/utils/fail"

type Client int

const (
	OVH Client = iota
	AWS
	Cloudferro
	Ebrc
	FlexibleEngine
	GCP
	Local
	OpenStack
	Outscale
	OpenTelekom
)

var (
	clientStringMap = map[string]Client{
		"ovh":            OVH,
		"aws":            AWS,
		"cloudferro":     Cloudferro,
		"ebrc":           Ebrc,
		"flexibleengine": FlexibleEngine,
		"gcp":            GCP,
		"local":          Local,
		"openstack":      OpenStack,
		"outscale":       Outscale,
		"opentelekom":    OpenTelekom,
	}

	clientEnumMap = map[Client]string{
		OVH:            "OVH",
		AWS:            "AWS",
		Cloudferro:     "Cloudferro",
		Ebrc:           "Ebrc",
		FlexibleEngine: "FlexibleEngine",
		GCP:            "GCP",
		Local:          "Local",
		OpenStack:      "OpenStack",
		Outscale:       "Outscale",
		OpenTelekom:    "Opentelekom",
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
