package utils

type EmailInterface interface {
	SendInvitationEmail(upn string, domain string)
}
