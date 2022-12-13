package commands

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

func Test_constructHostDefinitionStringFromCLI_1(t *testing.T) {
	name := "obsidian"
	theFlags := []cli.Flag{cli.IntFlag{
		Name: "gpu",
	}, cli.IntFlag{Name: "count", Value: 1}, cli.StringFlag{Name: "sizing"}}

	set := flag.NewFlagSet(name, flag.ContinueOnError)
	for _, f := range theFlags {
		f.Apply(set)
	}

	disaster := cli.NewContext(&cli.App{
		Name:   name,
		Usage:  "A new cli application",
		Flags:  theFlags,
		Writer: os.Stdout,
	}, set, nil)

	err := disaster.Set("count", "3")
	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}

	rv, err := constructHostDefinitionStringFromCLI(disaster, "sizing")
	if err != nil {
		t.Error(err.Error())
	}

	require.Contains(t, rv, ",")
	t.Log(rv)
}

func Test_constructHostDefinitionStringFromCLI_2(t *testing.T) {
	name := "obsidian"
	theFlags := []cli.Flag{cli.IntFlag{
		Name: "gpu",
	}, cli.IntFlag{Name: "count", Value: 1}, cli.StringFlag{Name: "sizing"}}

	set := flag.NewFlagSet(name, flag.ContinueOnError)
	for _, f := range theFlags {
		f.Apply(set)
	}

	disaster := cli.NewContext(&cli.App{
		Name:   name,
		Usage:  "A new cli application",
		Flags:  theFlags,
		Writer: os.Stdout,
	}, set, nil)

	rv, err := constructHostDefinitionStringFromCLI(disaster, "sizing")
	if err != nil {
		t.Error(err.Error())
	}

	require.NotContains(t, rv, ",")
	t.Log(rv)
}
