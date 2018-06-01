package utils

import (
	"time"
)

const (
	Address = "localhost:50051"
	//TimeoutCtxDefault default timeout for grpc command invocation
	TimeoutCtxDefault = 20 * time.Second
	//TimeoutCtxVM timeout for grpc command relative to VM creation
	TimeoutCtxVM = 2 * time.Minute
	//MetadataContainerName is the name of the Object Storage Container/Bucket used to store metadata
	MetadataContainerName string = "0.safescale"
)
