package main

import (
	"encoding/json"
	"fmt"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/nanobox-io/golang-scribble"
	_ "github.com/nanobox-io/golang-scribble"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type StoredCPUInfo struct {
	Id      string `bow:"key"`
	TenantName   string `json:"tenant_name,omitempty"`
	TemplateID   string `json:"template_id,omitempty"`
	TemplateName string `json:"template_name,omitempty"`
	ImageID   string `json:"image_id,omitempty"`
	ImageName string `json:"image_name,omitempty"`
	LastUpdated string `json:"last_updated,omitempty"`

	NumberOfCPU    int     `json:"number_of_cpu,omitempty"`
	NumberOfCore   int     `json:"number_of_core,omitempty"`
	NumberOfSocket int     `json:"number_of_socket,omitempty"`
	CPUFrequency   float64 `json:"cpu_frequency,omitempty"`
	CPUArch        string  `json:"cpu_arch,omitempty"`
	Hypervisor     string  `json:"hypervisor,omitempty"`
	CPUModel       string  `json:"cpu_model,omitempty"`
	RAMSize        float64 `json:"ram_size,omitempty"`
	RAMFreq        float64 `json:"ram_freq,omitempty"`
	GPU            int     `json:"gpu,omitempty"`
	GPUModel       string  `json:"gpu_model,omitempty"`
}

func collect() {
	_ = os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777)

	db, err := scribble.New(utils.AbsPathify("$HOME/.safescale/scanner/db"), nil)
	if err != nil {
		log.Fatal(err)
	}

	files, err := ioutil.ReadDir(utils.AbsPathify("$HOME/.safescale/scanner"))
	if err != nil {
		log.Fatal(err)
	}

	acpu := StoredCPUInfo{}

	for _, file := range files {
		if strings.Contains(file.Name(), "#") {

			theFile := fmt.Sprintf("$HOME/.safescale/scanner/%s", file.Name())

			log.Printf("Storing: %s", file.Name())

			byteValue, err := ioutil.ReadFile(utils.AbsPathify(theFile) )
			if err != nil {
				log.Fatal(err)
			}

			err = json.Unmarshal(byteValue, &acpu)
			if err != nil {
				log.Fatal(err)
			}

			acpu.Id = acpu.ImageID

			err = db.Write("images", acpu.TemplateName, acpu)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

}
