package result

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type Option[T any] func(*holder[T]) fail.Error

func WithPayload[T any](payload T) Option[T] {
	return func(r *holder[T]) fail.Error {
		r.payload = payload
		return nil
	}
}

func MarkAsSuccessful[T any]() Option[T] {
	return func(r *holder[T]) fail.Error {
		r.success = true
		return nil
	}
}

func MarkAsCompleted[T any]() Option[T] {
	return func(r *holder[T]) fail.Error {
		r.completed = true
		return nil
	}
}

func Lock[T any]() Option[T] {
	return func(r *holder[T]) fail.Error {
		r.frozen = true
		return nil
	}
}
