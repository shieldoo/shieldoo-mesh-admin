package main

import "fmt"

type Emailing struct {
}

func (e Emailing) SendInvitationEmail(upn string, domain string) {
	// Implement any emailng logic there
	fmt.Printf("Sending invitation email to %s for domain %s\n", upn, domain)
}
