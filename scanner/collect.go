package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/utils"
	_ "github.com/nanobox-io/golang-scribble"
	scribble "github.com/nanobox-io/golang-scribble"
)

// StoredCPUInfo ...
type StoredCPUInfo struct {
	Id string `bow:"key"`
	CPUInfo
}

func collect(tenantName string) error {
	serviceProvider, err := iaas.UseService(tenantName)
	if err != nil {
		return err
	}
	authOpts, err := serviceProvider.GetAuthOpts()
	if err != nil {
		return err
	}
	region, ok := authOpts.Get("Region")
	if !ok {
		return fmt.Errorf("Region value unset")
	}

	folder := fmt.Sprintf("images/%s/%s", serviceProvider.GetProvider(), region)

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
		theFile := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/scanner/%s", file.Name()))
		if strings.Contains(file.Name(), tenantName+"#") {
			log.Printf("Storing: %s", file.Name())

			byteValue, err := ioutil.ReadFile(theFile)
			if err != nil {
				log.Fatal(err)
			}

			err = json.Unmarshal(byteValue, &acpu)
			if err != nil {
				log.Fatal(err)
			}

			acpu.Id = acpu.ImageID

			err = db.Write(folder, acpu.TemplateName, acpu)
			if err != nil {
				log.Fatal(err)
			}
		}
		if !file.IsDir() {
			err := os.Remove(theFile)
			if err != nil {
				fmt.Printf("Error Supressing %s : %s", file.Name(), err.Error())
			}
		}
	}
	return nil
}
