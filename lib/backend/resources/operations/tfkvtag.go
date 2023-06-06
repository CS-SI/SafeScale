package operations

import (
	uuidpkg "github.com/gofrs/uuid"
)

type KeyValueTag struct {
	Id               string  `json:"Id"`
	Key              string  `json:"Key"`
	Value            *string `json:"Value"`
	WithDefaultValue bool    `json:"WithDefaultValue"`
}

func NewTfTag(key string) (*KeyValueTag, error) {
	uuid, err := uuidpkg.NewV4()
	if err != nil {
		return nil, err
	}
	return &KeyValueTag{Id: uuid.String(), Key: key, WithDefaultValue: false}, nil
}

func NewTfLabel(key string, value string) (*KeyValueTag, error) {
	uuid, err := uuidpkg.NewV4()
	if err != nil {
		return nil, err
	}
	return &KeyValueTag{Id: uuid.String(), Key: key, Value: &value, WithDefaultValue: true}, nil
}

// GetId get the Id
func (t *KeyValueTag) GetId() string {
	return t.Id
}

// GetKey get the Key
func (t *KeyValueTag) GetKey() string {
	return t.Key
}

// GetValue get the Value
func (t *KeyValueTag) GetValue() (string, error) {
	if t.WithDefaultValue {
		return *t.Value, nil
	}
	return "", nil
}

// HasDefaultValue get the WithDefaultValue
func (t *KeyValueTag) HasDefaultValue() bool {
	return t.WithDefaultValue
}
