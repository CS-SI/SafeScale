package resources

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type (
	networkTransaction = *networkTransactionImpl

	networkTransactionImpl struct {
		metadata.Transaction[*abstract.Network, *Network]
	}
)

func newNetworkTransaction(ctx context.Context, instance *Network) (networkTransaction, fail.Error) {
	if instance == nil {
		return nil, fail.InvalidParameterCannotBeNilError("instance")
	}

	trx, xerr := metadata.NewTransaction[*abstract.Network, *Network](ctx, instance)
	if xerr != nil {
		return nil, xerr
	}

	return &networkTransactionImpl{trx}, nil
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

// IsNull ...
func (networkTrx *networkTransactionImpl) IsNull() bool {
	return networkTrx == nil || networkTrx.Transaction.IsNull()
}

// FreeCIDRForSingleHost frees the CIDR index inside the Network 'Network'
func (networkTrx *networkTransactionImpl) FreeCIDRForSingleHost(ctx context.Context, index uint) fail.Error {
	if valid.IsNull(networkTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	return alterNetworkMetadataProperty(ctx, networkTrx, networkproperty.SingleHostsV1, func(p clonable.Clonable) fail.Error {
		nshV1, innerErr := lang.Cast[*propertiesv1.NetworkSingleHosts](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		nshV1.FreeSlot(index)
		return nil
	})
}
