package utils

import (
	"testing"
)

// TestGenerateRandomBytes calls utils.GenerateRandomBytes and checking len of returned array
func TestGenerateRandomBytes(t *testing.T) {
	arrlen := 24
	b := GenerateRandomBytes(arrlen)
	if len(b) != arrlen {
		t.Fatalf(`GenerateRandomBytes(%d) returns array of wrong len %d`, arrlen, len(b))
	}
}

// TestGenerateRandomString calls utils.GenerateRandomString and checking len of returned string
func TestGenerateRandomString(t *testing.T) {
	arrlen := 24
	b := GenerateRandomString(arrlen)
	if len(b) <= arrlen {
		t.Fatalf(`GenerateRandomString(%d) returns string of wrong len %d`, arrlen, len(b))
	}
}
