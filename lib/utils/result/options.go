package result

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type Option[T any] func(*holder[T]) fail.Error

// WithPayload sets the payload of the result Holder
func WithPayload[T any](payload T) Option[T] {
	return func(r *holder[T]) fail.Error {
		r.payload = payload
		return nil
	}
}

// TagSuccessFromCondition tags the holder as successful if b is true, to failed otherwise
func TagSuccessFromCondition[T any](b bool) Option[T] {
	return func(r *holder[T]) fail.Error {
		r.success = b
		return nil
	}
}

// TagCompletedFromError ...
func TagCompletedFromError[T any](err error) Option[T] {
	return func(r *holder[T]) fail.Error {
		r.err = err
		r.completed = err == nil
		return nil
	}
}

// TagFrozen freezes the cointent of the holder, making update impossible
func TagFrozen[T any]() Option[T] {
	return func(r *holder[T]) fail.Error {
		r.frozen = true
		return nil
	}
}
