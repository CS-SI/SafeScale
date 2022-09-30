package options

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type Options interface {
	Load(key string) (any, fail.Error)
	Store(key string, value any) (any, fail.Error)
}
