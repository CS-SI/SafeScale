//Package VolumeState defines an enum to represents Volume states life cycle
package VolumeState

//go:generate stringer -type=Enum

//Enum represents the state of a VM
type Enum int

const (
	//CREATING creating The volume is being created
	CREATING Enum = iota
	// AVAILABLE available	The volume is ready to attach to an instance.
	AVAILABLE
	// ATTACHING attaching	The volume is attaching to an instance.
	ATTACHING
	// DETACHING detaching	The volume is detaching from an instance.
	DETACHING
	//USED in-use	The volume is attached to an instance.
	USED
	//DELETING deleting	The volume is being deleted.
	DELETING
	//ERROR error cases:
	// error	A volume creation error occurred.
	// error_deleting	A volume deletion error occurred.
	// error_backing-up	A backup error occurred.
	// error_restoring	A backup restoration error occurred.
	// error_extending	An error occurred while attempting to extend a volume.
	ERROR
	//OTHER possible cases
	// backing-up	The volume is being backed up.
	// restoring-backup	A backup is being restored to the volume.
	// downloading	The volume is downloading an image.
	// uploading	The volume is being uploaded to an image.
	// retyping	The volume is changing type to another volume type.
	// extending	The volume is being extended.
	OTHER
)
