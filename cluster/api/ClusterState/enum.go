package ClusterState

//go:generate stringer -type=Enum

//Enum represents the state of a node
type Enum int

const (
	//Nominal the cluster is started and fully operational
	Nominal Enum = iota
	//Degraded the cluster is running but some key components are failing (typically a master)
	Degraded
	//Stopped the cluster is stopped
	Stopped
	//Initializing the cluster is initializing
	Initializing
	//Created the cluster is ready to be initialized
	Created
	//Creating the cluster is currently created
	Creating
	//Error when an error occured on gathering cluster state
	Error
	//Removed tells the struct still exist but the underlying cluster has been totally wiped out
	Removed
)
