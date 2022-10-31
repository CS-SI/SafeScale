package metadata

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

func Review[T clonable.Clonable](ctx context.Context, instance resources.Metadata, callback resources.ResourceCallback[T]) fail.Error {
	return instance.Review(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		casted, err := lang.Cast[T](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted, props)
	})
}

func ReviewProperty[T clonable.Clonable](ctx context.Context, instance resources.Metadata, property string, callback resources.PropertyCallback[T]) fail.Error {
	return instance.Review(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(property, func(p clonable.Clonable) fail.Error {
			casted, err := lang.Cast[T](p)
			if err != nil {
				return fail.Wrap(err)
			}

			return callback(casted)
		})
	})
}

func Inspect[T clonable.Clonable](ctx context.Context, instance resources.Metadata, callback resources.ResourceCallback[T], opts ...Option) fail.Error {
	return instance.Inspect(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		casted, err := lang.Cast[T](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted, props)
	}, opts...)
}

func InspectProperty[T clonable.Clonable](ctx context.Context, instance resources.Metadata, property string, callback resources.PropertyCallback[T], opts ...Option) fail.Error {
	return instance.InspectProperty(ctx, property, func(p clonable.Clonable) fail.Error {
		casted, err := lang.Cast[T](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted)
	}, opts...)
}

func Alter[T clonable.Clonable](ctx context.Context, instance resources.Metadata, callback resources.ResourceCallback[T], opts ...Option) fail.Error {
	return instance.Alter(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		casted, err := lang.Cast[T](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted, props)
	}, opts...)
}

func AlterProperty[T clonable.Clonable](ctx context.Context, instance resources.Metadata, property string, callback resources.PropertyCallback[T], opts ...Option) fail.Error {
	return instance.AlterProperty(ctx, property, func(p clonable.Clonable) fail.Error {
		casted, err := lang.Cast[T](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted)
	}, opts...)
}
