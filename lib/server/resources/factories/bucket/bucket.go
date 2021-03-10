package bucket

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// List retrieves all available buckets
func List(svc iaas.Service) ([]string, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	return svc.ListBuckets(objectstorage.RootPath)
}

// New instanciates a new bucket instance
func New(svc iaas.Service) (resources.Bucket, fail.Error) {
	return operations.NewBucket(svc)
}

// Load initializes the bucket with metadata from provider
func Load(svc iaas.Service, name string) (resources.Bucket, fail.Error) {
	return operations.LoadBucket(svc, name)
}
