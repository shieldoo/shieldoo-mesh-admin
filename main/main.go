package main

import (
	"github.com/shieldoo/shieldoo-mesh-admin"
)

func main() {
	// model encryptor plugin
	modelEncryptor := ModelEncyptor{Key: "TestKey1234567890"}

	cfg, _ := shieldoo.Init(modelEncryptor)

	// segment plugin
	var segment SegmentEvent
	cfg.Segment = segment

	// emailing plugin
	var emailing Emailing
	cfg.Emailing = emailing

	// logstore plugins
	LogInit()
	var logStore MyLogStore
	var secLogStore MySecurityLogStore
	cfg.LogStore = logStore
	cfg.SecurityLogStore = secLogStore

	shieldoo.Run()
}
