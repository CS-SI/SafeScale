package utils

import (
	"log"
	"net"
	"strconv"
	"time"
)

// New gets an available port
func New() (port int, err error) {

	// Create a new server without specifying a port
	// which will result in an open port being chosen
	server, err := net.Listen("tcp", ":0")

	// If there's an error it likely means no ports
	// are available or something else prevented finding
	// an open port
	if err != nil {
		return 0, err
	}

	// Defer the closing of the server so it closes
	defer func() {
		_ = server.Close()
	}()

	// Get the host string in the format "127.0.0.1:4444"
	hostString := server.Addr().String()

	// Split the host from the port
	_, portString, err := net.SplitHostPort(hostString)
	if err != nil {
		return 0, err
	}

	// Return the port as an int
	return strconv.Atoi(portString)
}

// Check if a port is available
func Check(port int) (status bool, err error) {

	// Concatenate a colon and the port
	host := ":" + strconv.Itoa(port)

	// Try to create a server with the port
	server, err := net.Listen("tcp", host)

	// if it fails then the port is likely taken
	if err != nil {
		return false, err
	}

	// close the server
	_ = server.Close()

	// we successfully used and closed the port
	// so it's now available to be used again
	return true, nil

}

func runAway(site string, port string) {
	timeout := time.Duration(1 * time.Second)
	_, err := net.DialTimeout("tcp", site+":"+port, timeout)
	if err != nil {
		log.Println("Site unreachable, error: ", err)
	}
}
