package Complexity

//go:generate stringer -type=Enum

//Enum represents the complexity of a cluster
type Enum int

const (

	//Simple is the simplest mode of cluster
	Simple Enum = iota
	//HighAvailability allows the cluster to be resistant to 1 master failure
	HighAvailability
	//HighVolume allows the cluster to be resistant to 2 master failures and is sized for high volume of agents
	HighVolume
)
