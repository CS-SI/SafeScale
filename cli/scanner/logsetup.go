package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/commonlog"
)

func init() {
	logrus.SetFormatter(commonlog.GetDefaultFormatter())
	logrus.SetLevel(logrus.DebugLevel)

	// Log as JSON instead of the default ASCII formatter.
	// log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example

	dirname := utils.AbsPathify("$HOME/.safescale")
	_ = os.MkdirAll(dirname, 0777)

	_, err := os.Stat(dirname)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Unable to create directory %s", dirname)
		} else {
			fmt.Printf("Directory %s stat error: %v", dirname, err)
		}
		os.Exit(1)
	}

	// DEV VAR
	session := ""
	if sessionCandidate := os.Getenv("SAFESCALE_LOG_SESSION"); sessionCandidate != "" {
		session = "-" + sessionCandidate
	}

	logFileName := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/scanner%s-session.log", session))
	file, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("Unable to access file %s, make sure the file is writable\n", logFileName)
		os.Exit(1)
	}

	log.SetOutput(io.MultiWriter(os.Stdout, file))
}
