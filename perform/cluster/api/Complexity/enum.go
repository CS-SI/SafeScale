package Complexity

//go:generate stringer -type=Enum

//Enum represents the complexity of a cluster
type Enum int

const (

	//Dev is the simplest mode of cluster
	Dev Enum = 1
	//Normal allows the cluster to be resistant to 1 master failure
	Normal Enum = 3
	//Volume allows the cluster to be resistant to 2 master failures and is sized for high volume of agents
	Volume Enum = 5
)
