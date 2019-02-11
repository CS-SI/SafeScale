package serialize

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

// CloneValue clones a source to a target
// source and destination have to be pointer actually
func CloneValue(source, target interface{}) error {
	var buffer bytes.Buffer
	err := gob.NewEncoder(&buffer).Encode(source)
	if err != nil {
		return fmt.Errorf("unable to encode source: %v", err)
	}

	err = gob.NewDecoder(&buffer).Decode(target)
	if err != nil {
		return fmt.Errorf("unable to encode to target: %v", err)
	}
	return err
}
