package authserver

import (
	"os"
	"time"

	"github.com/shieldoo/shieldoo-mesh-admin/utils"
	log "github.com/sirupsen/logrus"
)

var globjwtMaker Maker
var _cfg *utils.Config

func Init(cfg *utils.Config) {
	_cfg = cfg
	var err error
	globjwtMaker, err = NewJWTMaker(cfg.OAuthServer.Secret)
	if err != nil {
		log.Panic("Unable initialize OauthServer: ", err)
		os.Exit(1000)
	}
}

func CreateToken(upn string, access_id int, client_id string) (string, time.Time, error) {
	return globjwtMaker.CreateToken(
		upn,
		access_id,
		client_id,
		time.Duration(time.Second*time.Duration(_cfg.OAuthServer.Duration)))
}

func VerifyToken(token string) (*Payload, error) {
	return globjwtMaker.VerifyToken(token)
}
