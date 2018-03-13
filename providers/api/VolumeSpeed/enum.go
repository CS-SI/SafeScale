//Package VolumeSpeed defines an enum to represents Volume type
package VolumeSpeed

//go:generate stringer -type=Enum

//Enum represents the state of a VM
type Enum int

const (

	//SSD speed volume
	SSD Enum = iota
	//HDD speed volume.
	HDD
	//COLD speed volume
	COLD
)
