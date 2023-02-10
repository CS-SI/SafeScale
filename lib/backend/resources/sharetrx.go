package resources

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type (
	shareTransaction     = *shareTransactionImpl
	shareTransactionImpl struct {
		metadata.Transaction[*abstract.Share, *Share]
	}
)

func newShareTransaction(ctx context.Context, instance *Share) (shareTransaction, fail.Error) {
	if instance == nil {
		return nil, fail.InvalidParameterCannotBeNilError("instance")
	}

	trx, xerr := metadata.NewTransaction[*abstract.Share, *Share](ctx, instance)
	if xerr != nil {
		return nil, xerr
	}

	return &shareTransactionImpl{trx}, nil
}

func inspectShareMetadata(ctx context.Context, trx shareTransaction, callback func(*abstract.Share, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Inspect[*abstract.Share](ctx, trx, callback)
}

func inspectShareMetadataAbstract(ctx context.Context, trx shareTransaction, callback func(*abstract.Share) fail.Error) fail.Error {
	return metadata.InspectAbstract[*abstract.Share](ctx, trx, callback)
}

func inspectShareMetadataProperty[P clonable.Clonable](ctx context.Context, trx shareTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.InspectProperty[*abstract.Share, P](ctx, trx, property, callback)
}

func inspectShareMetadataProperties(ctx context.Context, trx shareTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.Share](ctx, trx, callback)
}

func alterShareMetadata(ctx context.Context, trx shareTransaction, callback func(*abstract.Share, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Alter[*abstract.Share](ctx, trx, callback)
}

func alterShareMetadataAbstract(ctx context.Context, trx shareTransaction, callback func(*abstract.Share) fail.Error) fail.Error {
	return metadata.AlterAbstract[*abstract.Share](ctx, trx, callback)
}

func alterShareMetadataProperty[P clonable.Clonable](ctx context.Context, trx shareTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.AlterProperty[*abstract.Share, P](ctx, trx, property, callback)
}

func alterShareMetadataProperties(ctx context.Context, trx shareTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.AlterProperties[*abstract.Share](ctx, trx, callback)
}

// IsNull ...
func (shareTrx *shareTransactionImpl) IsNull() bool {
	return shareTrx == nil || shareTrx.Transaction.IsNull()
}
