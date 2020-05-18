package bucket

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ErrorList retrieves all available buckets
func List(svc iaas.Service) ([]string, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	// tracer := concurrency.NewTracer(task, "", false).Entering()
	// defer tracer.OnExitTrace()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())
	return svc.ListBuckets(objectstorage.RootPath)
}

// New instanciates a new bucket instance
func New(svc iaas.Service) (resources.Bucket, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	return operations.NewBucket(svc)
}

// Load initializes the bucket with metadata from provider
func Load(svc iaas.Service, name string) (resources.Bucket, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be emtpy string")
	}
	return operations.LoadBucket(svc, name)
}
