package properties

import (
	"github.com/CS-SI/SafeScale/providers/model"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
)

// ModelHostTemplateToPropertyHostSize ...
func ModelHostTemplateToPropertyHostSize(ht *model.HostTemplate) *propsv1.HostSize {
	hs := propsv1.NewHostSize()
	hs.Cores = ht.Cores
	hs.RAMSize = ht.RAMSize
	hs.DiskSize = ht.DiskSize
	hs.GPUNumber = ht.GPUNumber
	hs.CPUFreq = ht.CPUFreq
	return hs
}

// ModelHostDefinitionToPropertyHostSize ...
func ModelHostDefinitionToPropertyHostSize(hd *model.HostDefinition) *propsv1.HostSize {
	hs := propsv1.NewHostSize()
	hs.Cores = hd.Cores
	hs.RAMSize = hd.RAMSize
	hs.DiskSize = hd.DiskSize
	hs.GPUNumber = hd.GPUNumber
	hs.CPUFreq = hd.CPUFreq
	return hs
}
