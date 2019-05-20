package utils

import (
	"fmt"
	"strconv"
	"strings"
)

// CIDRToIPv4Range converts CIDR to IPv4 range
func CIDRToIPv4Range(cidr string) (string, string, error) {
	start, end, err := CIDRToLongRange(cidr)
	if err != nil {
		return "", "", err
	}

	ipStart := LongToIPv4(start)
	ipEnd := LongToIPv4(end)

	return ipStart, ipEnd, nil
}

// CIDRToLongRange converts CIDR to IPv4 range
func CIDRToLongRange(cidr string) (uint32, uint32, error) {
	if cidr == "" {
		return 0, 0, fmt.Errorf("Invalid parameter 'cidr': can't be empty string")
	}

	var (
		ip    uint32 // ip address
		start uint32 // Start IP address range
		end   uint32 // End IP address range
	)

	splitted := strings.Split(cidr, "/")
	ip = IPv4ToLong(splitted[0])
	bits, _ := strconv.ParseUint(splitted[1], 10, 32)

	if start == 0 || start > ip {
		start = ip
	}

	ip = ip | (0xFFFFFFFF >> bits)
	if end < ip {
		end = ip
	}

	return start, end, nil
}

// IPv4ToLong converts IPv4 to uint32
func IPv4ToLong(ip string) uint32 {
	parts := [4]uint64{}

	for i, v := range strings.SplitN(ip, ".", 4) {
		parts[i], _ = strconv.ParseUint(v, 10, 32)
	}

	result := (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
	return uint32(result)
}

// LongToIPv4 converts uint32 to IP
func LongToIPv4(value uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", value>>24, (value&0x00FFFFFF)>>16, (value&0x0000FFFF)>>8, value&0x000000FF)
}
