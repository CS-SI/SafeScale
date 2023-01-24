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
	labelTransaction = metadata.Transaction[*abstract.Label, *Label]
)

func newLabelTransaction(ctx context.Context, instance *Label) (labelTransaction, fail.Error) {
	return metadata.NewTransaction[*abstract.Label, *Label](ctx, instance)
}

func inspectLabelMetadata(ctx context.Context, trx labelTransaction, callback func(*abstract.Label, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Inspect[*abstract.Label](ctx, trx, callback)
}

func inspectLabelMetadataCarried(ctx context.Context, trx labelTransaction, callback func(*abstract.Label) fail.Error) fail.Error {
	return metadata.InspectCarried[*abstract.Label](ctx, trx, callback)
}

func inspectLabelMetadataProperty[P clonable.Clonable](ctx context.Context, trx labelTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.InspectProperty[*abstract.Label, P](ctx, trx, property, callback)
}

func inspectLabelMetadataProperties(ctx context.Context, trx labelTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.Label](ctx, trx, callback)
}

func reviewLabelMetadata(ctx context.Context, trx labelTransaction, callback func(*abstract.Label, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Review[*abstract.Label](ctx, trx, callback)
}

func reviewLabelMetadataCarried(ctx context.Context, trx labelTransaction, callback func(ahc *abstract.Label) fail.Error) fail.Error {
	return metadata.ReviewCarried[*abstract.Label](ctx, trx, callback)
}

func reviewLabelMetadataProperty[P clonable.Clonable](ctx context.Context, trx labelTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.ReviewProperty[*abstract.Label, P](ctx, trx, property, callback)
}

func reviewLabelMetadataProperties(ctx context.Context, trx labelTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.ReviewProperties[*abstract.Label](ctx, trx, callback)
}

func alterLabelMetadata(ctx context.Context, trx labelTransaction, callback func(*abstract.Label, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Alter[*abstract.Label](ctx, trx, callback)
}

func alterLabelMetadataCarried(ctx context.Context, trx labelTransaction, callback func(*abstract.Label) fail.Error) fail.Error {
	return metadata.AlterCarried[*abstract.Label](ctx, trx, callback)
}

func alterLabelMetadataProperty[P clonable.Clonable](ctx context.Context, trx labelTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.AlterProperty[*abstract.Label, P](ctx, trx, property, callback)
}

func alterLabelMetadataProperties(ctx context.Context, trx labelTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.Label](ctx, trx, callback)
}
