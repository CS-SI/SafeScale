package metadata

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
)

func Review[A clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], callback ResourceCallback[A], opts ...options.Option) fail.Error {
	return trx.review(ctx, func(carried A, props *serialize.JSONProperties) fail.Error {
		return callback(carried, props)
	}, opts...)
}

// ReviewAbstract ...
func ReviewAbstract[A clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], callback CarriedCallback[A], opts ...options.Option) fail.Error {
	return trx.reviewAbstract(ctx, func(carried A) fail.Error {
		return callback(carried)
	}, opts...)
}

// ReviewProperty ...
func ReviewProperty[A, P clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], property string, callback PropertyCallback[P], opts ...options.Option) fail.Error {
	return trx.reviewProperty(ctx, property, func(p clonable.Clonable) fail.Error {
		casted, err := lang.Cast[P](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted)
	}, opts...)
}

// ReviewProperties ...
func ReviewProperties[A clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], callback AllPropertiesCallback, opts ...options.Option) fail.Error {
	return trx.reviewProperties(ctx, func(props *serialize.JSONProperties) fail.Error {
		return callback(props)
	}, opts...)
}

// Inspect ...
func Inspect[A clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], callback ResourceCallback[A], opts ...options.Option) fail.Error {
	return trx.inspect(ctx, func(carried A, props *serialize.JSONProperties) fail.Error {
		return callback(carried, props)
	}, opts...)
}

// InspectAbstract ...
func InspectAbstract[A clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], callback CarriedCallback[A], opts ...options.Option) fail.Error {
	return trx.inspectAbstract(ctx, func(carried A) fail.Error {
		return callback(carried)
	}, opts...)
}

// InspectProperty ...
func InspectProperty[A, P clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], property string, callback PropertyCallback[P], opts ...options.Option) fail.Error {
	return trx.inspectProperty(ctx, property, func(p clonable.Clonable) fail.Error {
		casted, err := lang.Cast[P](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted)
	}, opts...)
}

// InspectProperties ...
func InspectProperties[A clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], callback AllPropertiesCallback, opts ...options.Option) fail.Error {
	return trx.inspectProperties(ctx, func(props *serialize.JSONProperties) fail.Error {
		return callback(props)
	}, opts...)
}

// Alter ...
func Alter[A clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], callback ResourceCallback[A], opts ...options.Option) fail.Error {
	return trx.alter(ctx, func(carried A, props *serialize.JSONProperties) fail.Error {
		return callback(carried, props)
	}, opts...)
}

// AlterAbstract ...
func AlterAbstract[A clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], callback CarriedCallback[A], opts ...options.Option) fail.Error {
	return trx.alterAbstract(ctx, func(carried A) fail.Error {
		return callback(carried)
	}, opts...)
}

// AlterProperty ...
func AlterProperty[A, P clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], property string, callback PropertyCallback[P], opts ...options.Option) fail.Error {
	return trx.alterProperty(ctx, property, func(p clonable.Clonable) fail.Error {
		casted, err := lang.Cast[P](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted)
	}, opts...)
}

// AlterProperties ...
func AlterProperties[A clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], callback AllPropertiesCallback, opts ...options.Option) fail.Error {
	return trx.alterProperties(ctx, func(props *serialize.JSONProperties) fail.Error {
		return callback(props)
	}, opts...)
}
