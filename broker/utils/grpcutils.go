package brokerd

import (
	"context"
	"log"
	"strings"
	"time"

	pb "github.com/SafeScale/broker"
	"google.golang.org/grpc"
)

const (
	address = "localhost:50051"
	//TimeoutCtxDefault default timeout for grpc command invocation
	TimeoutCtxDefault = 20 * time.Second
	//TimeoutCtxVM timeout for grpc command relative to VM creation
	TimeoutCtxVM = 2 * time.Minute
)

//GetConnection returns a connection to GRPC server
func GetConnection() *grpc.ClientConn {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	return conn
}

//GetContext return a context for grpc commands
func GetContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	// Contact the server and print out its response.
	return context.WithTimeout(context.Background(), timeout)
}

//GetReference return a reference from the name or id given in the pb.Reference
func GetReference(in *pb.Reference) string {
	var ref string
	name := in.GetName()
	if strings.TrimSpace(name) != "" {
		ref = name
	}
	id := in.GetID()
	if strings.TrimSpace(id) != "" {
		ref = id
	}
	return ref
}
