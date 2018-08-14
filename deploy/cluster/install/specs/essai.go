package main

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/spf13/viper"
)

func main() {
	v := viper.New()
	v.SetConfigName("kubernetes")
	v.AddConfigPath(".")
	err := v.ReadInConfig()
	if err != nil {
		panic(err.Error())
	}

	spew.Dump(v.AllSettings())
}
