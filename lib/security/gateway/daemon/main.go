package main

import "github.com/CS-SI/SafeScale/lib/security/gateway"

func main() {
	gateway.Start(":443")
}
