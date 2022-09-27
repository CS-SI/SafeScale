package options

import (
	"reflect"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Value returns the value of a key
func Value[O any](opts Options, key string) (O, fail.Error) {
	var out O
	anon, xerr := opts.Load(key)
	if xerr != nil {
		return out, xerr
	}

	var ok bool
	out, ok = anon.(O)
	if !ok {
		return out, fail.InconsistentError("failed to convert value to expected type '%s'", reflect.TypeOf(out).String())
	}

	return out, nil
}

// ValueOrDefault returns the value of key in options, or the default value if not found
func ValueOrDefault[T any](opts Options, key string, value T) (T, fail.Error) {
	var empty T
	out, xerr := Value[T](opts, key)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return value, nil
		default:
			return empty, xerr
		}
	}

	return out, nil
}

// ValueOrSet returns the value of key in options, or set the key with the value and returns it
// returns:
// - value, false, nil: there was no key in options but now it's set
// - value, true, nil: key was found in options
// - zero-value, false, fail.Error: an error occurred
func ValueOrSet[T any](opts Options, key string, value T) (T, bool, fail.Error) {
	var empty T
	out, xerr := Value[T](opts, key)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			xerr = Set(opts, key, value)
			if xerr != nil {
				return empty, false, xerr
			}

			return value, false, nil

		default:
			return empty, false, xerr
		}
	}

	return out, true, nil
}

// Set adds or changes value of key in options
func Set[T any](opts Options, key string, value T) fail.Error {
	_, xerr := opts.Store(key, value)
	return xerr
}

// Add sets the key value if key is not in options, fails if key already in options
func Add[O any](opts Options, key string, value O) fail.Error {
	_, found, xerr := ValueOrSet(opts, key, value)
	if xerr == nil && found {
		return fail.DuplicateError("failed to add key '%s' in options; already there", key)
	}

	return nil
}
