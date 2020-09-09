package main

import "github.com/CS-SI/SafeScale/lib/security/gateway"

func main() {
	runsok := make(chan bool)
	gateway.Start(":443", runsok)
	<-runsok
}
