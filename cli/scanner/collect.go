package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils"
	_ "github.com/nanobox-io/golang-scribble"
	scribble "github.com/nanobox-io/golang-scribble"
)

// StoredCPUInfo ...
type StoredCPUInfo struct {
	Id string `bow:"key"`
	CPUInfo
}

func collect(tenantName string) error {
	cmd := exec.Command("safescale", "tenant", "set", tenantName)
	if err := cmd.Run(); err != nil {
		return err
	}

	serviceProvider, err := iaas.UseService(tenantName)
	if err != nil {
		return err
	}
	authOpts, err := serviceProvider.GetAuthenticationOptions()
	if err != nil {
		return err
	}
	region, ok := authOpts.Get("Region")
	if !ok {
		return fmt.Errorf("Region value unset")
	}

	folder := fmt.Sprintf("images/%s/%s", serviceProvider.GetName(), region)

	err = os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777)
	if err != nil {
		log.Fatal(err)
	}

	db, err := scribble.New(utils.AbsPathify("$HOME/.safescale/scanner/db"), nil)
	if err != nil {
		log.Fatal(err)
	}

	files, err := ioutil.ReadDir(utils.AbsPathify("$HOME/.safescale/scanner"))
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		acpu := StoredCPUInfo{}
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
