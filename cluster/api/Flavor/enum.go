package Flavor

//go:generate stringer -type=Enum

//Enum represents the flavor of a cluster, in other words what technology is used behind the scene
type Enum int

const (
	DCOS Enum = iota
)
