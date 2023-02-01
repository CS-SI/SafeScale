package metadata

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
)

func Review[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback ResourceCallback[A], opts ...options.Option) fail.Error {
	return trx.review(ctx, func(carried A, props *serialize.JSONProperties) fail.Error {
		return callback(carried, props)
	}, opts...)
}

// ReviewAbstract ...
func ReviewAbstract[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback AbstractCallback[A], opts ...options.Option) fail.Error {
	return trx.reviewAbstract(ctx, func(carried A) fail.Error {
		return callback(carried)
	}, opts...)
}

// ReviewProperty ...
func ReviewProperty[A abstract.Abstract, P clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], property string, callback PropertyCallback[P], opts ...options.Option) fail.Error {
	return trx.reviewProperty(ctx, property, func(p clonable.Clonable) fail.Error {
		casted, err := lang.Cast[P](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted)
	}, opts...)
}

// ReviewProperties ...
func ReviewProperties[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback AllPropertiesCallback, opts ...options.Option) fail.Error {
	return trx.reviewProperties(ctx, func(props *serialize.JSONProperties) fail.Error {
		return callback(props)
	}, opts...)
}

// Inspect ...
func Inspect[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback ResourceCallback[A], opts ...options.Option) fail.Error {
	return trx.inspect(ctx, func(carried A, props *serialize.JSONProperties) fail.Error {
		return callback(carried, props)
	}, opts...)
}

// InspectAbstract ...
func InspectAbstract[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback AbstractCallback[A], opts ...options.Option) fail.Error {
	return trx.inspectAbstract(ctx, func(carried A) fail.Error {
		return callback(carried)
	}, opts...)
}

// InspectProperty ...
func InspectProperty[A abstract.Abstract, P clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], property string, callback PropertyCallback[P], opts ...options.Option) fail.Error {
	return trx.inspectProperty(ctx, property, func(p clonable.Clonable) fail.Error {
		casted, err := lang.Cast[P](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted)
	}, opts...)
}

// InspectProperties ...
func InspectProperties[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback AllPropertiesCallback, opts ...options.Option) fail.Error {
	return trx.inspectProperties(ctx, func(props *serialize.JSONProperties) fail.Error {
		return callback(props)
	}, opts...)
}

// Alter ...
func Alter[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback ResourceCallback[A], opts ...options.Option) fail.Error {
	return trx.alter(ctx, func(carried A, props *serialize.JSONProperties) fail.Error {
		return callback(carried, props)
	}, opts...)
}

// AlterAbstract ...
func AlterAbstract[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback AbstractCallback[A], opts ...options.Option) fail.Error {
	return trx.alterAbstract(ctx, func(carried A) fail.Error {
		return callback(carried)
	}, opts...)
}

// AlterProperty ...
func AlterProperty[A abstract.Abstract, P clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], property string, callback PropertyCallback[P], opts ...options.Option) fail.Error {
	return trx.alterProperty(ctx, property, func(p clonable.Clonable) fail.Error {
		casted, err := lang.Cast[P](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted)
	}, opts...)
}

// AlterProperties ...
func AlterProperties[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback AllPropertiesCallback, opts ...options.Option) fail.Error {
	return trx.alterProperties(ctx, func(props *serialize.JSONProperties) fail.Error {
		return callback(props)
	}, opts...)
}
