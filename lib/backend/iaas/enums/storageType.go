package enums

import "github.com/CS-SI/SafeScale/v22/lib/utils/fail"

type StorageType int

const (
	S3 StorageType = iota
	Swift
	AzureStorage
	GCE
	Google
)

var (
	storageStringMap = map[string]StorageType{
		"s3":     S3,
		"swift":  Swift,
		"azure":  AzureStorage,
		"gce":    GCE,
		"google": Google,
	}

	storageEnumMap = map[StorageType]string{
		S3:           "S3",
		Swift:        "Swift",
		AzureStorage: "Azure",
		GCE:          "GCE",
		Google:       "Google",
	}
)

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
