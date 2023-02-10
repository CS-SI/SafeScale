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
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type (
	volumeTransaction = *volumeTransactionImpl

	volumeTransactionImpl struct {
		metadata.Transaction[*abstract.Volume, *Volume]
	}
)

func newVolumeTransaction(ctx context.Context, instance *Volume) (volumeTransaction, fail.Error) {
	if instance == nil {
		return nil, fail.InvalidParameterCannotBeNilError("instance")
	}

	trx, xerr := metadata.NewTransaction[*abstract.Volume, *Volume](ctx, instance)
	if xerr != nil {
		return nil, xerr
	}

	return &volumeTransactionImpl{trx}, nil
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

// IsNull ...
func (volumeTrx *volumeTransactionImpl) IsNull() bool {
	return volumeTrx == nil || volumeTrx.Transaction.IsNull()
}

// GetSpeed ...
func (volumeTrx *volumeTransactionImpl) GetSpeed(ctx context.Context) (volumespeed.Enum, fail.Error) {
	if valid.IsNull(volumeTrx) {
		return 0, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return 0, fail.InvalidParameterCannotBeNilError("ctx")
	}

	var speed volumespeed.Enum
	xerr := inspectVolumeMetadataAbstract(ctx, volumeTrx, func(av *abstract.Volume) fail.Error {
		speed = av.Speed
		return nil
	})
	return speed, debug.InjectPlannedFail(xerr)
}

// GetSize ...
func (volumeTrx *volumeTransactionImpl) GetSize(ctx context.Context) (int, fail.Error) {
	if valid.IsNull(volumeTrx) {
		return 0, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return 0, fail.InvalidParameterCannotBeNilError("ctx")
	}

	var size int
	xerr := inspectVolumeMetadataAbstract(ctx, volumeTrx, func(av *abstract.Volume) fail.Error {
		size = av.Size
		return nil
	})
	return size, debug.InjectPlannedFail(xerr)
}
