package utils

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	baseTimestamp time.Time
	emptyFieldMap logrus.FieldMap
)

// MyFormatter ...
type MyFormatter struct {
	logrus.TextFormatter
	pid string
}

func GetDefaultFormatter() *MyFormatter {
	return &MyFormatter{
		TextFormatter: logrus.TextFormatter{
			ForceColors:            true,
			TimestampFormat:        "2006-01-02 15:04:05.000",
			FullTimestamp:          true,
			DisableLevelTruncation: true,
		}}
}

// Format ...
func (f *MyFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	if f.TextFormatter.DisableLevelTruncation && f.TextFormatter.ForceColors {
		if f.pid == "" {
			f.pid = strconv.Itoa(os.Getpid())
			f.pid = strings.Repeat(" ", 5-len(f.pid)) + f.pid
		}
		bc, err := f.TextFormatter.Format(entry)
		ticket := string(bc)
		// replaced := strings.Replace(ticket, "[20", ""+strings.Repeat(" ", 8-len(entry.Level.String()))+"[" + f.pid + "][20", 1)
		replaced := strings.Replace(ticket, "[20", ""+strings.Repeat(" ", 8-len(entry.Level.String()))+"[20", 1)
		replaced = strings.Replace(replaced, "] ", "]["+entry.Level.String()+"]["+f.pid+"] ", 1)

		return []byte(replaced), err
	}

	return f.TextFormatter.Format(entry)
}
