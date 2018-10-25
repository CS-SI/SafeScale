package providers

import (
	log "github.com/sirupsen/logrus"
	"io"
	"os"
)

func init() {
	// Log as JSON instead of the default ASCII formatter.
	// log.SetFormatter(&log.JSONFormatter{})

	log.SetFormatter(&log.TextFormatter{ForceColors:true, TimestampFormat : "2006-01-02 15:04:05", FullTimestamp:true})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	file, err := os.OpenFile("providers-session.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}

	bfile, err := os.OpenFile("brokerd-session.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}

	log.SetOutput(io.MultiWriter(os.Stdout, file, bfile))
}