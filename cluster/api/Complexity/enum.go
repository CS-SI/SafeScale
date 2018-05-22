package Complexity

//go:generate stringer -type=Enum

//Enum represents the complexity of a cluster
type Enum int

const (

	//Dev is the simplest mode of cluster
	Dev Enum = 1
	//HighAvailability allows the cluster to be resistant to 1 master failure
	HighAvailability Enum = 3
	//HighVolume allows the cluster to be resistant to 2 master failures and is sized for high volume of agents
	HighVolume Enum = 5
)
