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
	bucketTransaction     = *bucketTransactionImpl
	bucketTransactionImpl struct {
		metadata.Transaction[*abstract.Bucket, *Bucket]
	}
)

func newBucketTransaction(ctx context.Context, instance *Bucket) (*bucketTransactionImpl, fail.Error) {
	if instance == nil {
		return nil, fail.InvalidParameterCannotBeNilError("instance")
	}

	trx, xerr := metadata.NewTransaction[*abstract.Bucket, *Bucket](ctx, instance)
	if xerr != nil {
		return nil, xerr
	}

	return &bucketTransactionImpl{trx}, nil
}

func inspectBucketMetadata(ctx context.Context, trx bucketTransaction, callback func(*abstract.Bucket, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Inspect[*abstract.Bucket](ctx, trx, callback)
}

func inspectBucketMetadataAbstract(ctx context.Context, trx bucketTransaction, callback func(*abstract.Bucket) fail.Error) fail.Error {
	return metadata.InspectAbstract[*abstract.Bucket](ctx, trx, callback)
}

func inspectBucketMetadataProperty[P clonable.Clonable](ctx context.Context, trx bucketTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.InspectProperty[*abstract.Bucket, P](ctx, trx, property, callback)
}

func inspectBucketMetadataProperties(ctx context.Context, trx bucketTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.Bucket](ctx, trx, callback)
}

func alterBucketMetadata(ctx context.Context, trx bucketTransaction, callback func(*abstract.Bucket, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Alter[*abstract.Bucket](ctx, trx, callback)
}

func alterBucketMetadataAbstract(ctx context.Context, trx bucketTransaction, callback func(*abstract.Bucket) fail.Error) fail.Error {
	return metadata.AlterAbstract[*abstract.Bucket](ctx, trx, callback)
}

func alterBucketMetadataProperty[P clonable.Clonable](ctx context.Context, trx bucketTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.AlterProperty[*abstract.Bucket, P](ctx, trx, property, callback)
}

func alterBucketMetadataProperties(ctx context.Context, trx bucketTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.AlterProperties[*abstract.Bucket](ctx, trx, callback)
}

// IsNull ...
func (bucketTrx *bucketTransactionImpl) IsNull() bool {
	return bucketTrx == nil || bucketTrx.Transaction.IsNull()
}
