package resources

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type (
	volumeTransaction = metadata.Transaction[*abstract.Volume, *Volume]
)

func newVolumeTransaction(ctx context.Context, instance *Volume) (volumeTransaction, fail.Error) {
	return metadata.NewTransaction[*abstract.Volume, *Volume](ctx, instance)
}

func inspectVolumeMetadata(ctx context.Context, trx volumeTransaction, callback func(*abstract.Volume, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Inspect[*abstract.Volume](ctx, trx, callback)
}

func inspectVolumeMetadataAbstract(ctx context.Context, trx volumeTransaction, callback func(*abstract.Volume) fail.Error) fail.Error {
	return metadata.InspectAbstract[*abstract.Volume](ctx, trx, callback)
}

func inspectVolumeMetadataProperty[P clonable.Clonable](ctx context.Context, trx volumeTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.InspectProperty[*abstract.Volume, P](ctx, trx, property, callback)
}

func inspectVolumeMetadataProperties(ctx context.Context, trx volumeTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.Volume](ctx, trx, callback)
}

func reviewVolumeMetadata(ctx context.Context, trx volumeTransaction, callback func(*abstract.Volume, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Review[*abstract.Volume](ctx, trx, callback)
}

func reviewVolumeMetadataAbstract(ctx context.Context, trx volumeTransaction, callback func(ahc *abstract.Volume) fail.Error) fail.Error {
	return metadata.ReviewAbstract[*abstract.Volume](ctx, trx, callback)
}

func reviewVolumeMetadataProperty[P clonable.Clonable](ctx context.Context, trx volumeTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.ReviewProperty[*abstract.Volume, P](ctx, trx, property, callback)
}

func reviewVolumeMetadataProperties(ctx context.Context, trx volumeTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.ReviewProperties[*abstract.Volume](ctx, trx, callback)
}

func alterVolumeMetadata(ctx context.Context, trx volumeTransaction, callback func(*abstract.Volume, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Alter[*abstract.Volume](ctx, trx, callback)
}

func alterVolumeMetadataAbstract(ctx context.Context, trx volumeTransaction, callback func(*abstract.Volume) fail.Error) fail.Error {
	return metadata.AlterAbstract[*abstract.Volume](ctx, trx, callback)
}

func alterVolumeMetadataProperty[P clonable.Clonable](ctx context.Context, trx volumeTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.AlterProperty[*abstract.Volume, P](ctx, trx, property, callback)
}

func alterVolumeMetadataProperties(ctx context.Context, trx volumeTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.AlterProperties[*abstract.Volume](ctx, trx, callback)
}

// trxGetSpeed ...
// Intended to be used when instance is notoriously not nil
func (instance *Volume) trxGetSpeed(ctx context.Context, volumeTrx volumeTransaction) (volumespeed.Enum, fail.Error) {
	var speed volumespeed.Enum
	xerr := reviewVolumeMetadataAbstract(ctx, volumeTrx, func(av *abstract.Volume) fail.Error {
		speed = av.Speed
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return speed, nil
}

// unsafeGetSize ...
// Intended to be used when instance is notoriously not nil
func (instance *Volume) trxGetSize(ctx context.Context, volumeTrx volumeTransaction) (int, fail.Error) {
	var size int
	xerr := reviewVolumeMetadataAbstract(ctx, volumeTrx, func(av *abstract.Volume) fail.Error {
		size = av.Size
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return size, nil
}
