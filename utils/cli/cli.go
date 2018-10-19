/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * cli is a command line interface parameter manager, using docopt-parser for syntax validation
 * then using the results of docopt-parser to process the commands.
 * This package purpose is to combine the flexibility of command line definition of docopt with
 * a upper level of abstraction for the handling of the parameters.
 */

package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/utils/cli/ExitCode"
	docopt "github.com/CS-SI/SafeScale/utils/cli/docopt-parser"
)

var (
	// docoptArguments is used to store docopt argument parsed
	docoptArguments map[string]interface{}

	// RebrandPrefix stores the optional prefix of the cli program
	RebrandPrefix string
)

// Handler ...
type Handler func(*Command)

// Command ...
type Command struct {
	// Keyword is the main keyword the Command manages
	Keyword string
	// Aliases contains the alternative keywords the Command manages
	Aliases []string

	// Before is some optional code to call before calling Process
	Before Handler
	// Process is the code executed to handle the command
	Process Handler
	// After is some optional code to call after calling Process
	After Handler

	// Help contains help corresponding to the command
	Help *HelpContent

	// Commands contains a list of all the subcommands of this command
	Commands []*Command

	// stringMap establishes a link between command string and *Command
	stringMap map[string]*Command

	// app is a "pointer" to App instance using the Command
	app *App
}

// IsKeywordSet tells if a specific keyword is set
func (c *Command) IsKeywordSet(keyword string) bool {
	if docoptArguments == nil {
		panic("docopt not called yet!")
	}

	var ok bool
	var anon interface{}
	splitted := strings.Split(keyword, ",")
	for _, v := range splitted {
		if anon, ok = docoptArguments[v]; ok {
			if anon.(bool) {
				return true
			}
		}
	}
	return false
}

// Flag extract the value of a boolean option
// options contains a list of options
func (c *Command) Flag(option string, def bool) bool {
	var (
		ok   bool
		anon interface{}
	)

	splitted := strings.Split(option, ",")
	for _, opt := range splitted {
		opt = strings.TrimSpace(opt)
		anon, ok = docoptArguments[opt]
		if !ok || anon == nil {
			continue
		}
	}
	if ok && anon != nil {
		return anon.(bool)
	}
	return def
}

// Option extracts the value of a untyped option
func (c *Command) Option(option string, parameter string) interface{} {
	var (
		ok   bool
		anon interface{}
	)

	splitted := strings.Split(option, ",")
	for _, opt := range splitted {
		opt = strings.TrimSpace(opt)
		anon, ok = docoptArguments[opt]
		if !ok || anon == nil {
			continue
		}
	}
	if ok && anon != nil {
		return anon
	}
	if !ok {
		fmt.Printf("Missing parameter '%s' for '%s'\n", parameter, option)
		c.ShowHelp()
	}
	return nil
}

// StringOption extracts the value of a string option
// options contains a list of options (format -x or --xxx) separated by commas
func (c *Command) StringOption(option string, parameter string, def string) string {
	anon := c.Option(option, parameter)
	if anon != nil {
		return anon.(string)
	}
	return def
}

// StringSliceOption extracts the value of a slice of strings option
// options contains a list of options (format -x or --xxx) separated by commas
func (c *Command) StringSliceOption(option string, parameter string, def []string) []string {
	anon := c.Option(option, parameter)
	if anon != nil {
		return anon.([]string)
	}
	return def
}

// IntOption returns the integer value of the option 'option',
// where value is named 'parameter' in the docopt usage
func (c *Command) IntOption(option string, parameter string, def int) int {
	anon := c.Option(option, parameter)
	if anon != nil {
		strVal := anon.(string)
		val, err := strconv.Atoi(strVal)
		if err == nil {
			return val
		}
		_, _ = fmt.Fprintf(os.Stderr, "Invalid integer value '%s' for option '%s'! Ignored.", strVal, option)
	}
	return def
}

// FloatOption returns the float64 value of the option 'option',
// where value is named 'parameter' in the docopt usage
// 'def' is the default value to use if the 'option' is not set.
func (c *Command) FloatOption(option string, parameter string, def float64) float64 {
	anon := c.Option(option, parameter)
	if anon != nil {
		value, err := strconv.ParseFloat(anon.(string), 64)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(int(ExitCode.Run))
		}
		return value
	}
	return def
}

// StringArgument returns a string corresponding to the content of an argument
func (c *Command) StringArgument(arg string, def string) string {
	arg = strings.TrimSpace(arg)
	anon, ok := docoptArguments[arg]
	if ok && anon != nil {
		return anon.(string)
	}
	return def
}

// SliceArgument returns a slice corresponding to the content of an argument
func (c *Command) SliceArgument(arg string, def []interface{}) []interface{} {
	arg = strings.TrimSpace(arg)
	anon, ok := docoptArguments[arg]
	if ok && anon != nil {
		return anon.([]interface{})
	}
	return def
}

// StringSliceArgument returns a slice of strings corresponding to the content of an argument
func (c *Command) StringSliceArgument(arg string, def []string) []string {
	arg = strings.TrimSpace(arg)
	anon, ok := docoptArguments[arg]
	if ok && anon != nil {
		return anon.([]string)
	}
	return def
}

// init is called to initialize working data of a Command
func (c *Command) init(a *App) {
	// Gives Command reference to App instance
	c.app = a

	if len(c.stringMap) == 0 {
		// Builds c.stringMap to be able to find quickly the command
		// associate with each keyword (including aliases)
		c.stringMap = map[string]*Command{}
		for _, v := range c.Commands {
			options := []string{v.Keyword}
			options = append(options, v.Aliases...)
			for _, item := range options {
				c.stringMap[item] = v
			}
		}
	}
}

// ShowHelp is called to display help contextually
func (c *Command) ShowHelp() {
	var ok bool
	for k, item := range c.stringMap {
		if _, ok = docoptArguments[k].(bool); ok {
			item.init(c.app)
			item.ShowHelp()
			return
		}
	}

	fmt.Println(c.Help.Assemble(c.app.Name))
}

// App ...
type App struct {
	// Name is the name of the program
	Name string

	// usage contains the docopt usage
	usage string
	// root correspond to level 0 of the command
	root *Command
	// parser is the docopt parser
	//parser *docopt.Parser
}

// NewApp creates a new App
func NewApp(usage string, c *Command) *App {
	app := &App{
		Name:  c.Keyword,
		usage: usage,
		root:  c,
	}
	c.init(app)
	return app
}

// Run interprets cli parameters and reacts accordingly
func (a *App) Run(args []string) {
	// Disables part of docopt that displays errors and managed global flags
	// a.parser = &docopt.Parser{
	// 	SkipHelpFlags: false,
	// 	HelpHandler: func(msg string) {
	// 		if msg != "" {
	// 			fmt.Print(output)
	// 		}
	// 	},
	// }

	if args == nil {
		args = os.Args[1:]
	}

	// Parses the cli arguments and validates them to docopt usage
	var err error
	docoptArguments, err = docopt.ParseArgs(a.usage, args)
	if err != nil {
		msg := err.Error()
		if _, ok := err.(*docopt.UserError); ok {
			if msg != "" {
				fmt.Print(msg)
			}
			a.root.ShowHelp()
			os.Exit(1)
		}
		if _, ok := err.(*docopt.LanguageError); ok {
			panic(msg)
		}
		fmt.Println(msg)
		os.Exit(1)
	}

	// Processes commands and their options
	dispatch(a.root)
}

// ShowHelp displays help
func (a *App) ShowHelp() {
	a.root.ShowHelp()
}

// dispatch realizes the code flow to execute what is asked on cli
func dispatch(c *Command) {
	if c == nil {
		panic("c is nil!")
	}

	// 1st step: initializes working data of the command
	c.init(c.app)

	// 2nd: executes c.Before if defined
	if c.Before != nil {
		c.Before(c)
	}

	// 3rd step: search for an appropriate subcommand
	var (
		ok, found bool
		subcmd    *Command
		anon      interface{}
	)
	for _, subcmd = range c.Commands {
		allKeywords := []string{subcmd.Keyword}
		allKeywords = append(allKeywords, subcmd.Aliases...)
		for _, alias := range allKeywords {
			if anon, ok = docoptArguments[alias]; !ok || anon == nil {
				continue
			}
			if anon.(bool) {
				found = true
			}
		}
		if found {
			break
		}
	}
	// for key, subcmd = range c.stringMap {
	// 	if anon, ok = docoptArguments[key]; !ok || anon == nil {
	// 		continue
	// 	}
	// 	if anon.(bool) {
	// 		break
	// 	}
	// }

	// 4th step: executes current command Process if it's defined
	if c.Process != nil {
		c.Process(c)
	}

	// 5th step: if subcommand found, dispatches to it
	if subcmd != nil {
		subcmd.app = c.app
		dispatch(subcmd)
	}

	// 4th step, executes After if defined
	if c.After != nil {
		c.After(c)
	}
}
