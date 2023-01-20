package commands

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_parametersToMap(t *testing.T) {
	var hell []string
	hell = append(hell, "login=wat")
	hell = append(hell, "pass=wot")
	hell = append(hell, "feat:lol=wat")
	hell = append(hell, "feat:passz=wot")

	dm, _ := parametersToMap(hell)
	assert.Equalf(t, "wat", dm["login"], "first key failed")
	assert.Equalf(t, "wot", dm["pass"], "second key failed")
}
