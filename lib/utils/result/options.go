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

// MarkAsSuccessful ...
func MarkAsSuccessful[T any]() Option[T] {
	return func(r *holder[T]) fail.Error {
		r.success = true
		return nil
	}
}

// MarkAsFailed sets the error of the result Holder
func MarkAsFailed[T any](err error) Option[T] {
	return func(r *holder[T]) fail.Error {
		r.err = err
		return nil
	}
}

// MarkAsCompleted ...
func MarkAsCompleted[T any]() Option[T] {
	return func(r *holder[T]) fail.Error {
		r.completed = true
		return nil
	}
}

// Lock ...
func Lock[T any]() Option[T] {
	return func(r *holder[T]) fail.Error {
		r.frozen = true
		return nil
	}
}
