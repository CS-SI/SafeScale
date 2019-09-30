package stacks

// LocalConfiguration configuration options
type LocalConfiguration struct {
	ImagesJSONPath string
	// Local Path of the json file defining the templates
	TemplatesJSONPath string
	// Local Path of the libvirt pool where all disks created by libvirt come from and are stored
	LibvirtStorage string
	// Connection identifier to the visualization device
	URI string
}
