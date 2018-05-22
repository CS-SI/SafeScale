package NodeState

//go:generate stringer -type=Enum

//Enum represents the state of a node
type Enum int

const (

	//Started the node is started and available
	Started Enum = iota
	//Disabled the node is started but not available to take load
	Disabled
	//Stopped the node is stopped
	Stopped
)
