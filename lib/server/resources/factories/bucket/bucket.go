package bucket

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ErrorList retrieves all available buckets
func List(svc iaas.Service) ([]string, error) {
	if svc == nil {
		return nil, fail.InvalidParameterReport("svc", "cannot be nil")
	}

	// tracer := concurrency.NewTracer(task, "", false).Entering()
	// defer tracer.OnExitTrace()
	// defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	return svc.ListBuckets(objectstorage.RootPath)
}

// New instanciates a new bucket instance
func New(svc iaas.Service) (resources.Bucket, error) {
	if svc == nil {
		return nil, fail.InvalidParameterReport("svc", "cannot be nil")
	}
	return operations.NewBucket(svc)
}

// Load initializes the bucket with metadata from provider
func Load(svc iaas.Service, name string) (resources.Bucket, error) {
	if svc == nil {
		return nil, fail.InvalidParameterReport("svc", "cannot be nil")
	}
	if name == "" {
		return nil, fail.InvalidParameterReport("name", "cannot be emtpy string")
	}
	return operations.LoadBucket(svc, name)
}
