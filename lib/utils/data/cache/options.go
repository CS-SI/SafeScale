package cache

import (
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

const (
	OptionOnMissKeyword        = "on_miss"
	OptionOnMissTimeoutKeyword = "on_miss_timeout"
)

// MissEventOption returns []data.ImmutableKeyValue options to use on cache miss with timeout
func MissEventOption(fn func() (Cacheable, fail.Error), timeout time.Duration) []data.ImmutableKeyValue {
	if timeout <= 0 {
		return []data.ImmutableKeyValue{
			data.NewImmutableKeyValue(OptionOnMissKeyword, func() (Cacheable, fail.Error) {
				return nil, fail.InvalidRequestError("invalid timeout for function provided to react on cache miss event: cannot be less or equal to 0")
			}),
			data.NewImmutableKeyValue(OptionOnMissTimeoutKeyword, timeout),
		}
	}

	if fn != nil {
		return []data.ImmutableKeyValue{
			data.NewImmutableKeyValue(OptionOnMissKeyword, fn),
			data.NewImmutableKeyValue(OptionOnMissTimeoutKeyword, timeout),
		}
	}

	return []data.ImmutableKeyValue{
		data.NewImmutableKeyValue(OptionOnMissKeyword, func() (Cacheable, fail.Error) {
			return nil, fail.InvalidRequestError("invalid function provided to react on cache miss event: cannot be nil")
		}),
		data.NewImmutableKeyValue(OptionOnMissTimeoutKeyword, timeout),
	}
}
