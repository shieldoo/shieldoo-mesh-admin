package model

import (
	"net"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
)

func SendInvitationEmail(upn string) {
	log.Debug("SendInvitationEmail: ", upn)
	u, err := url.Parse(_cfg.Server.URI)
	if err != nil {
		log.Error("email send - cannot parse server uri:", err)
		return
	}
	host := u.Host
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(u.Host)
	}
	_cfg.Emailing.SendInvitationEmail(upn, host)
}
