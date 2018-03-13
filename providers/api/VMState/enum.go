package VMState

//go:generate stringer -type=Enum

//Enum represents the state of a VM
type Enum int

const (
	/*STOPPED VM is stopped*/
	STOPPED Enum = iota
	/*STARTING VM is starting*/
	STARTING
	/*STARTED VM is started*/
	STARTED
	/*STOPPING VM is stopping*/
	STOPPING
	/*ERROR VM is in error state*/
	ERROR
)
