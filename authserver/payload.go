package authserver

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

type Payload struct {
	ID        uuid.UUID `json:"id"`
	UPN       string    `json:"upn"`
	AccessID  int       `json:"access_id"`
	ClientID  string    `json:"client_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

var (
	ErrInvalidToken = errors.New("token is invalid")
	ErrExpiredToken = errors.New("token has expired")
)

func NewPayload(upn string, access_id int, client_id string, duration time.Duration) (*Payload, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	payload := &Payload{
		ID:        tokenID,
		UPN:       upn,
		AccessID:  access_id,
		ClientID:  client_id,
		IssuedAt:  time.Now().UTC(),
		ExpiredAt: time.Now().UTC().Add(duration),
	}
	return payload, nil
}

func (payload *Payload) Valid() error {
	if time.Now().UTC().After(payload.ExpiredAt) {
		return ErrExpiredToken
	}
	return nil
}
