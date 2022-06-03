package ssh

import (
	"io/ioutil"
	"os"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// CreateTempFileFromString creates a temporary file containing 'content'
func CreateTempFileFromString(content string, filemode os.FileMode) (*os.File, fail.Error) {
	defaultTmpDir := os.TempDir()

	f, err := ioutil.TempFile(defaultTmpDir, "")
	if err != nil {
		return nil, fail.ExecutionError(err, "failed to create temporary file")
	}
	_, err = f.WriteString(content)
	if err != nil {
		return nil, fail.ExecutionError(err, "failed to wrote string to temporary file")
	}

	err = f.Chmod(filemode)
	if err != nil {
		return nil, fail.ExecutionError(err, "failed to change temporary file access rights")
	}

	err = f.Close()
	if err != nil {
		return nil, fail.ExecutionError(err, "failed to close temporary file")
	}

	return f, nil
}
