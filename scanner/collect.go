package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/CS-SI/SafeScale/utils"
	"github.com/nanobox-io/golang-scribble"
	_ "github.com/nanobox-io/golang-scribble"
)

// StoredCPUInfo ...
type StoredCPUInfo struct {
	Id           string `bow:"key"`
	CPUInfo
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

			byteValue, err := ioutil.ReadFile(utils.AbsPathify(theFile))
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
