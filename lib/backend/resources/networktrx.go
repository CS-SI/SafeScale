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
	networkTransaction = metadata.Transaction[*abstract.Network, *Network]
)

func newNetworkTransaction(ctx context.Context, instance *Network) (networkTransaction, fail.Error) {
	return metadata.NewTransaction[*abstract.Network, *Network](ctx, instance)
}

func inspectNetworkMetadata(ctx context.Context, trx networkTransaction, callback func(*abstract.Network, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Inspect[*abstract.Network](ctx, trx, callback)
}

func inspectNetworkMetadataAbstract(ctx context.Context, trx networkTransaction, callback func(*abstract.Network) fail.Error) fail.Error {
	return metadata.InspectAbstract[*abstract.Network](ctx, trx, callback)
}

func inspectNetworkMetadataProperty[P clonable.Clonable](ctx context.Context, trx networkTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.InspectProperty[*abstract.Network, P](ctx, trx, property, callback)
}

func inspectNetworkMetadataProperties(ctx context.Context, trx networkTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.Network](ctx, trx, callback)
}

func reviewNetworkMetadata(ctx context.Context, trx networkTransaction, callback func(*abstract.Network, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Review[*abstract.Network](ctx, trx, callback)
}

func reviewNetworkMetadataAbstract(ctx context.Context, trx networkTransaction, callback func(ahc *abstract.Network) fail.Error) fail.Error {
	return metadata.ReviewAbstract[*abstract.Network](ctx, trx, callback)
}

func reviewNetworkMetadataProperty[P clonable.Clonable](ctx context.Context, trx networkTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.ReviewProperty[*abstract.Network, P](ctx, trx, property, callback)
}

func reviewNetworkMetadataProperties(ctx context.Context, trx networkTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.ReviewProperties[*abstract.Network](ctx, trx, callback)
}

func alterNetworkMetadata(ctx context.Context, trx networkTransaction, callback func(*abstract.Network, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Alter[*abstract.Network](ctx, trx, callback)
}

func alterNetworkMetadataAbstract(ctx context.Context, trx networkTransaction, callback func(*abstract.Network) fail.Error) fail.Error {
	return metadata.AlterAbstract[*abstract.Network](ctx, trx, callback)
}

func alterNetworkMetadataProperty[P clonable.Clonable](ctx context.Context, trx networkTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.AlterProperty[*abstract.Network, P](ctx, trx, property, callback)
}

func alterNetworkMetadataProperties(ctx context.Context, trx networkTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.AlterProperties[*abstract.Network](ctx, trx, callback)
}
