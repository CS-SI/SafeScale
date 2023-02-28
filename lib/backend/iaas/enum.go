package iaas

import "github.com/CS-SI/SafeScale/v22/lib/utils/fail"

type Client int
type StorageType int

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
)

const (
	S3 StorageType = iota
	Swift
	Azure
	GCE
	Google
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
	}

	storageStringMap = map[string]StorageType{
		"s3":     S3,
		"swift":  Swift,
		"azure":  Azure,
		"gce":    GCE,
		"google": Google,
	}

	storageEnumMap = map[StorageType]string{
		S3:     "S3",
		Swift:  "Swift",
		Azure:  "Azure",
		GCE:    "GCE",
		Google: "Google",
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

func ParseStorage(s string) (StorageType, error) {
	var (
		p  StorageType
		ok bool
	)
	if p, ok = storageStringMap[s]; !ok {
		return p, fail.NotFoundError("failed to find a Storage type matching with '%s'", s)
	}
	return p, nil
}

func (p StorageType) String() string {
	if s, ok := storageEnumMap[p]; ok {
		return s
	}
	return ""
}
