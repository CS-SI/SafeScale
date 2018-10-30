package flexibleengine

import (
	"strings"

	"github.com/CS-SI/SafeScale/iaas/resource"
	"github.com/CS-SI/SafeScale/model"
)

func addGPUCfg(tpl *resource.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// GetTemplate returns the Template referenced by id
func (p *FlexibleEngine) GetTemplate(id string) (*model.HostTemplate, error) {
	tpl, err := p.stack.GetTemplate(id)
	if tpl != nil {
		addGPUCfg(tpl)
	}
	return tpl, err
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (p *FlexibleEngine) ListTemplates() ([]model.HostTemplate, error) {
	allTemplates, err := p.stack.ListTemplates()
	if err != nil {
		return nil, err
	}
	var tpls []resource.HostTemplate
	for _, tpl := range allTemplates {
		addGPUCfg(&tpl)
		tpls = append(tpls, tpl)
	}

	return tpls, nil
}

func isWindowsImage(image model.Image) bool {
	return strings.Contains(strings.ToLower(image.Name), "windows")
}

func isBMSImage(image model.Image) bool {
	return strings.HasPrefix(strings.ToUpper(image.Name), "OBS-BMS") ||
		strings.HasPrefix(strings.ToUpper(image.Name), "OBS_BMS")
}

// ListImages lists available OS images
func (p *FlexibleEngine) ListImages(all) ([]model.Image, error) {
	images, err := p.stack.ListImages()
	if err != nil {
		return nil, err
	}
	if all {
		return images, nil
	}

	imageFilter := filters.NewFilter(isWindowsImage).Not().And(filters.NewFilter(isBMSImage).Not())
	return filters.FilterImages(images, imageFilter), nil
}
