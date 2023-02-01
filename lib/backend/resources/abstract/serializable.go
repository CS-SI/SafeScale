package abstract

import "github.com/CS-SI/SafeScale/v22/lib/utils/fail"

//go:generate minimock -o mocks/mock_serializable.go -i github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract.Serializable

// Serializable to transform structs from and to json
type Serializable interface {
	Serialize() ([]byte, fail.Error)
	Deserialize(buf []byte) (ferr fail.Error)
}
