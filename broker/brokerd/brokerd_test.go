package main

import (
	"fmt"
	"testing"

	"golang.org/x/net/context"

	pb "github.com/SafeScale/brokerd"
	// srv "github.com/SafeScale/brokerd/server"
)

func Test_List(t *testing.T) {
	s := networkServiceServer{}
	req := &pb.TenantName{Name: "TestOvh"}
	resp, err := s.List(context.Background(), req)
	if err != nil {
		t.Errorf("Something gone wrong (%v)", err)
	}

	for i, network := range resp.GetNetworks() {
		// log.Printf("Network %d: %s", i, network)
		fmt.Printf("Network %d: %s", i, network)
	}
}
