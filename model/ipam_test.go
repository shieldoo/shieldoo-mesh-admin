package model

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func IpamTestCanonicalize(*testing.T) {
	tests := []string{
		"87.70.141.1/22",
		"36.18.154.103/12",
		"62.62.197.11/29",
		"67.137.119.181/4",
		"192.168.0.96/28",
		"192.168.240.0/20",
	}

	for _, test := range tests {
		fmt.Printf("%-18s -> %s\n", test, canonicalize(test))
	}
}

func IpamTestContains(t *testing.T) {
	_, actualcidr, _ := net.ParseCIDR("192.168.240.0/20")
	contains := actualcidr.Contains(net.ParseIP("192.168.240.9"))
	assert.True(t, contains, "192.168.240.0/20 must contain 192.168.240.9")
}
