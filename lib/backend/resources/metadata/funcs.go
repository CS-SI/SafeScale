package metadata

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
)

func Review[T clonable.Clonable](ctx context.Context, instance Metadata, callback ResourceCallback[T]) fail.Error {
	return instance.Review(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		casted, err := lang.Cast[T](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted, props)
	})
}

func ReviewProperty[T clonable.Clonable](ctx context.Context, instance Metadata, property string, callback PropertyCallback[T]) fail.Error {
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

func Inspect[T clonable.Clonable](ctx context.Context, instance Metadata, callback ResourceCallback[T], opts ...options.Option) fail.Error {
	return instance.Inspect(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		casted, err := lang.Cast[T](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted, props)
	}, opts...)
}

func InspectProperty[T clonable.Clonable](ctx context.Context, instance Metadata, property string, callback PropertyCallback[T], opts ...options.Option) fail.Error {
	return instance.InspectProperty(ctx, property, func(p clonable.Clonable) fail.Error {
		casted, err := lang.Cast[T](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted)
	}, opts...)
}

func Alter[T clonable.Clonable](ctx context.Context, instance Metadata, callback ResourceCallback[T], opts ...options.Option) fail.Error {
	return instance.Alter(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		casted, err := lang.Cast[T](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted, props)
	}, opts...)
}

func AlterProperty[T clonable.Clonable](ctx context.Context, instance Metadata, property string, callback PropertyCallback[T], opts ...options.Option) fail.Error {
	return instance.AlterProperty(ctx, property, func(p clonable.Clonable) fail.Error {
		casted, err := lang.Cast[T](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted)
	}, opts...)
}
