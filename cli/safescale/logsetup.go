package main

import (
	"io"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/commonlog"
)

func init() {
	log.SetFormatter(commonlog.GetDefaultFormatter())
	log.SetLevel(log.DebugLevel)

	// Log as JSON instead of the default ASCII formatter.
	// log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	_ = os.MkdirAll(utils.AbsPathify("$HOME/.safescale"), 0777)
	file, err := os.OpenFile(utils.AbsPathify("$HOME/.safescale/safescale-session.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}

	log.SetOutput(io.MultiWriter(os.Stdout, file))
}
