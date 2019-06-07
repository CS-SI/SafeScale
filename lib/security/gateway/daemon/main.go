package main

import "github.com/CS-SI/SafeScale/security/gateway"

func main() {
	gateway.Start(":443")
}
