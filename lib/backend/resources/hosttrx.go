package resources

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type hostTransaction = metadata.Transaction[*abstract.HostCore, *Host]

func newHostTransaction(ctx context.Context, instance *Host) (hostTransaction, fail.Error) {
	return metadata.NewTransaction[*abstract.HostCore, *Host](ctx, instance)
}

func inspectHostMetadata(ctx context.Context, ht hostTransaction, callback func(*abstract.HostCore, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Inspect[*abstract.HostCore](ctx, ht, callback)
}

func inspectHostMetadataCarried(ctx context.Context, ht hostTransaction, callback func(ahc *abstract.HostCore) fail.Error) fail.Error {
	return metadata.InspectCarried[*abstract.HostCore](ctx, ht, callback)
}

func inspectHostMetadataProperty[P clonable.Clonable](ctx context.Context, ht hostTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.InspectProperty[*abstract.HostCore, P](ctx, ht, property, callback)
}

func inspectHostMetadataProperties(ctx context.Context, ht hostTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.HostCore](ctx, ht, callback)
}

func reviewHostMetadata(ctx context.Context, ht hostTransaction, callback func(*abstract.HostCore, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Review[*abstract.HostCore](ctx, ht, callback)
}

func reviewHostMetadataCarried(ctx context.Context, ht hostTransaction, callback func(ahc *abstract.HostCore) fail.Error) fail.Error {
	return metadata.ReviewCarried[*abstract.HostCore](ctx, ht, callback)
}

func reviewHostMetadataProperty[P clonable.Clonable](ctx context.Context, ht hostTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.ReviewProperty[*abstract.HostCore, P](ctx, ht, property, callback)
}

func reviewHostMetadataProperties(ctx context.Context, ht hostTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.ReviewProperties[*abstract.HostCore](ctx, ht, callback)
}

func alterHostMetadata(ctx context.Context, ht hostTransaction, callback func(*abstract.HostCore, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Alter[*abstract.HostCore](ctx, ht, callback)
}

func alterHostMetadataCarried(ctx context.Context, ht hostTransaction, callback func(ahc *abstract.HostCore) fail.Error) fail.Error {
	return metadata.AlterCarried[*abstract.HostCore](ctx, ht, callback)
}

func alterHostMetadataProperty[P clonable.Clonable](ctx context.Context, ht hostTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.AlterProperty[*abstract.HostCore, P](ctx, ht, property, callback)
}

func alterHostMetadataProperties(ctx context.Context, ht hostTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.HostCore](ctx, ht, callback)
}
