package operations

type TfVolumeAttachment struct {
	Name     string
	Identity string

	AttachedHostId string
	AttachedDiskId string
}
