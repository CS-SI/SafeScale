package resources

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/labelproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type (
	labelTransaction = *labelTransactionImpl

	labelTransactionImpl struct {
		metadata.Transaction[*abstract.Label, *Label]
	}
)

func newLabelTransaction(ctx context.Context, instance *Label) (*labelTransactionImpl, fail.Error) {
	if instance == nil {
		return nil, fail.InvalidParameterCannotBeNilError("instance")
	}

	trx, xerr := metadata.NewTransaction[*abstract.Label, *Label](ctx, instance)
	if xerr != nil {
		return nil, xerr
	}

	return &labelTransactionImpl{trx}, nil
}

func inspectLabelMetadata(ctx context.Context, trx labelTransaction, callback func(*abstract.Label, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Inspect[*abstract.Label](ctx, trx, callback)
}

func inspectLabelMetadataAbstract(ctx context.Context, trx labelTransaction, callback func(*abstract.Label) fail.Error) fail.Error {
	return metadata.InspectAbstract[*abstract.Label](ctx, trx, callback)
}

func inspectLabelMetadataProperty[P clonable.Clonable](ctx context.Context, trx labelTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.InspectProperty[*abstract.Label, P](ctx, trx, property, callback)
}

func inspectLabelMetadataProperties(ctx context.Context, trx labelTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.Label](ctx, trx, callback)
}

func alterLabelMetadata(ctx context.Context, trx labelTransaction, callback func(*abstract.Label, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Alter[*abstract.Label](ctx, trx, callback)
}

func alterLabelMetadataAbstract(ctx context.Context, trx labelTransaction, callback func(*abstract.Label) fail.Error) fail.Error {
	return metadata.AlterAbstract[*abstract.Label](ctx, trx, callback)
}

func alterLabelMetadataProperty[P clonable.Clonable](ctx context.Context, trx labelTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.AlterProperty[*abstract.Label, P](ctx, trx, property, callback)
}

func alterLabelMetadataProperties(ctx context.Context, trx labelTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.AlterProperties[*abstract.Label](ctx, trx, callback)
}

// IsNull ...
func (labelTrx *labelTransactionImpl) IsNull() bool {
	return labelTrx == nil || labelTrx.Transaction.IsNull()
}

// UnbindFromHost removes Host from Label metadata, unbinding Host from Label
// Note: still need to call Host.UnbindLabel to remove reference of Label in Host...
func (labelTrx *labelTransactionImpl) UnbindFromHost(ctx context.Context, hostTrx hostTransaction) (ferr fail.Error) {
	if valid.IsNull(labelTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostTrx == nil {
		return fail.InvalidParameterCannotBeNilError("hostTrx")
	}

	hostName := hostTrx.GetName()
	hostID, err := hostTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	return alterLabelMetadataProperty(ctx, labelTrx, labelproperty.HostsV1, func(labelHostsV1 *propertiesv1.LabelHosts) fail.Error {
		// If the Label does not reference this Host, consider it a success
		_, ok := labelHostsV1.ByID[hostID]
		if ok {
			delete(labelHostsV1.ByID, hostID)
			delete(labelHostsV1.ByName, hostName)
		}
		return nil
	})
}

// BindToHost binds Host to the Label
func (labelTrx *labelTransactionImpl) BindToHost(ctx context.Context, hostTrx hostTransaction, value string) (ferr fail.Error) {
	if valid.IsNull(labelTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostTrx == nil {
		return fail.InvalidParameterCannotBeNilError("hostTrx")
	}

	hostName := hostTrx.GetName()
	hostID, err := hostTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	xerr := alterLabelMetadata(ctx, labelTrx, func(alabel *abstract.Label, props *serialize.JSONProperties) fail.Error {
		isTag := !alabel.HasDefault
		return props.Alter(labelproperty.HostsV1, func(p clonable.Clonable) fail.Error {
			labelHostsV1, innerErr := clonable.Cast[*propertiesv1.LabelHosts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			// If the tag has this host, consider it a success
			_, ok := labelHostsV1.ByID[hostID]
			if !ok {
				if isTag {
					value = ""
				}
				labelHostsV1.ByID[hostID] = value
				labelHostsV1.ByName[hostName] = value
			}
			return nil
		})
	})
	return debug.InjectPlannedFail(xerr)
}
