package operations

import (
	"context"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type Option func(clu *resources.Cluster) error

func NewCluster(inctx context.Context, svc iaas.Service, opts ...Option) (_ resources.Cluster, ferr fail.Error) {
	if len(opts) > 0 {
		return NewTfCluster(inctx, svc)
	}
	return NewClassicCluster(inctx, svc)
}

// NewClassicCluster is the constructor of resources.Cluster struct
func NewClassicCluster(inctx context.Context, svc iaas.Service) (_ *ClassicCluster, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	initial := &abstract.ClusterIdentity{}
	coreInstance, xerr := NewCore(svc, clusterKind, clustersFolderName, initial)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &ClassicCluster{
		MetadataCore: coreInstance,
		cluID:        initial,
	}
	xerr = instance.startRandomDelayGenerator(ctx, 0, 2000)
	if xerr != nil {
		return nil, xerr
	}

	instance.nodeIPs = make(data.IndexedListOfStrings)
	instance.masterIPs = make(data.IndexedListOfStrings)

	return instance, nil
}
