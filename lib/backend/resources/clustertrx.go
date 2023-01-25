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
	clusterTransaction = metadata.Transaction[*abstract.Cluster, *Cluster]
)

func newClusterTransaction(ctx context.Context, instance *Cluster) (clusterTransaction, fail.Error) {
	return metadata.NewTransaction[*abstract.Cluster, *Cluster](ctx, instance)
}

func inspectClusterMetadata(ctx context.Context, trx clusterTransaction, callback func(*abstract.Cluster, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Inspect[*abstract.Cluster](ctx, trx, callback)
}

func inspectClusterMetadataAbstract(ctx context.Context, trx clusterTransaction, callback func(*abstract.Cluster) fail.Error) fail.Error {
	return metadata.InspectAbstract[*abstract.Cluster](ctx, trx, callback)
}

func inspectClusterMetadataProperty[P clonable.Clonable](ctx context.Context, trx clusterTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.InspectProperty[*abstract.Cluster, P](ctx, trx, property, callback)
}

func inspectClusterMetadataProperties(ctx context.Context, trx clusterTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.Cluster](ctx, trx, callback)
}

func reviewClusterMetadata(ctx context.Context, trx clusterTransaction, callback func(*abstract.Cluster, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Review[*abstract.Cluster](ctx, trx, callback)
}

func reviewClusterMetadataAbstract(ctx context.Context, trx clusterTransaction, callback func(ahc *abstract.Cluster) fail.Error) fail.Error {
	return metadata.ReviewAbstract[*abstract.Cluster](ctx, trx, callback)
}

func reviewClusterMetadataProperty[P clonable.Clonable](ctx context.Context, trx clusterTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.ReviewProperty[*abstract.Cluster, P](ctx, trx, property, callback)
}

func reviewClusterMetadataProperties(ctx context.Context, trx clusterTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.ReviewProperties[*abstract.Cluster](ctx, trx, callback)
}

func alterClusterMetadata(ctx context.Context, trx clusterTransaction, callback func(*abstract.Cluster, *serialize.JSONProperties) fail.Error) fail.Error {
	return alterClusterMetadata(ctx, trx, callback)
}

func alterClusterMetadataAbstract(ctx context.Context, trx clusterTransaction, callback func(*abstract.Cluster) fail.Error) fail.Error {
	return metadata.AlterAbstract[*abstract.Cluster](ctx, trx, callback)
}

func alterClusterMetadataProperty[P clonable.Clonable](ctx context.Context, trx clusterTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.AlterProperty[*abstract.Cluster, P](ctx, trx, property, callback)
}

func alterClusterMetadataProperties(ctx context.Context, trx clusterTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.Cluster](ctx, trx, callback)
}
