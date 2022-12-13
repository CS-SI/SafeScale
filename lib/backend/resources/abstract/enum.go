package abstract

//go:generate stringer -type=Enum

// Enum ...
type Enum int

const (
	UnknownResource Enum = iota
	ClusterResource
	HostResource
	LabelResource
	NetworkResource
	ObjectStorageBucketResource
	SecurityGroupResource
	SubnetResource
	VolumeResource
	ShareResource
	FeatureResource
)
