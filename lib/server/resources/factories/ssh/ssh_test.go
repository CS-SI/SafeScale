package ssh

import (
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestNewConnector(t *testing.T) {
	theConf := ssh.NewConfig("", "", 0, "you", "xxx", 0, "", nil, nil)
	got, err := NewConnector(theConf, ConnectorWithLib())
	if err != nil {
		t.Error(err)
	}

	nomo := spew.Sdump(got)
	assert.Contains(t, nomo, "bylib")
}

func TestNewConnectorCli(t *testing.T) {
	theConf := ssh.NewConfig("", "", 0, "you", "xxx", 0, "", nil, nil)
	got, err := NewConnector(theConf, ConnectorWithCli())
	if err != nil {
		t.Error(err)
	}

	nomo := spew.Sdump(got)
	assert.Contains(t, nomo, "bycli")
}
