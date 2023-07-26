package authserver

import "time"

type Maker interface {
	CreateToken(upn string, access_id int, client_id string, duration time.Duration) (string, time.Time, error)
	VerifyToken(token string) (*Payload, error)
}
