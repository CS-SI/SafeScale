package options

import (
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type options struct {
	m sync.Map
}

func New() *options {
	return &options{}
}

// Load returns the value of key in options
func (o *options) Load(key string) (any, fail.Error) {
	if valid.IsNull(o) {
		return nil, fail.InvalidInstanceError()
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	out, ok := o.m.Load(key)
	if !ok {
		return nil, fail.NotFoundError("failed to find key '%s' in options", key)
	}

	return out, nil
}

// Store sets the value of key in options
func (o *options) Store(key string, value any) (any, fail.Error) {
	if valid.IsNull(o) {
		return nil, fail.InvalidInstanceError()
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	o.m.Store(key, value)
	return value, nil
}
