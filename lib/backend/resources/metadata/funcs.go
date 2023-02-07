package metadata

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

// Inspect ...
func Inspect[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback ResourceCallback[A]) fail.Error {
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if trx == nil {
		return fail.InvalidParameterCannotBeNilError("trx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	return trx.inspect(ctx, func(carried A, props *serialize.JSONProperties) fail.Error {
		return callback(carried, props)
	})
}

// InspectAbstract ...
func InspectAbstract[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback AbstractCallback[A]) fail.Error {
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if trx == nil {
		return fail.InvalidParameterCannotBeNilError("trx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	return trx.inspectAbstract(ctx, func(carried A) fail.Error {
		return callback(carried)
	})
}

// InspectProperty ...
func InspectProperty[A abstract.Abstract, P clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], property string, callback PropertyCallback[P]) fail.Error {
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if trx == nil {
		return fail.InvalidParameterCannotBeNilError("trx")
	}
	if property == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("property")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	return trx.inspectProperty(ctx, property, func(p clonable.Clonable) fail.Error {
		casted, err := lang.Cast[P](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted)
	})
}

// InspectProperties ...
func InspectProperties[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback AllPropertiesCallback) fail.Error {
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if trx == nil {
		return fail.InvalidParameterCannotBeNilError("trx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	return trx.inspectProperties(ctx, func(props *serialize.JSONProperties) fail.Error {
		return callback(props)
	})
}

// Alter ...
func Alter[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback ResourceCallback[A]) fail.Error {
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if trx == nil {
		return fail.InvalidParameterCannotBeNilError("trx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	return trx.alter(ctx, func(carried A, props *serialize.JSONProperties) fail.Error {
		return callback(carried, props)
	})
}

// AlterAbstract ...
func AlterAbstract[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback AbstractCallback[A]) fail.Error {
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if trx == nil {
		return fail.InvalidParameterCannotBeNilError("trx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	return trx.alterAbstract(ctx, func(carried A) fail.Error {
		return callback(carried)
	})
}

// AlterProperty ...
func AlterProperty[A abstract.Abstract, P clonable.Clonable](ctx context.Context, trx Transaction[A, Metadata[A]], property string, callback PropertyCallback[P]) fail.Error {
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if trx == nil {
		return fail.InvalidParameterCannotBeNilError("trx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	return trx.alterProperty(ctx, property, func(p clonable.Clonable) fail.Error {
		casted, err := lang.Cast[P](p)
		if err != nil {
			return fail.Wrap(err)
		}

		return callback(casted)
	})
}

// AlterProperties ...
func AlterProperties[A abstract.Abstract](ctx context.Context, trx Transaction[A, Metadata[A]], callback AllPropertiesCallback) fail.Error {
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if trx == nil {
		return fail.InvalidParameterCannotBeNilError("trx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	return trx.alterProperties(ctx, func(props *serialize.JSONProperties) fail.Error {
		return callback(props)
	})
}
