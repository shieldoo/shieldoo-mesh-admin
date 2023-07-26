package shieldoo

import (
	"encoding/json"

	"github.com/shieldoo/shieldoo-mesh-admin/app"
	"github.com/shieldoo/shieldoo-mesh-admin/authserver"
	"github.com/shieldoo/shieldoo-mesh-admin/graph"
	"github.com/shieldoo/shieldoo-mesh-admin/job"
	"github.com/shieldoo/shieldoo-mesh-admin/logstore"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
	"github.com/shieldoo/shieldoo-mesh-admin/myjwt"
	"github.com/shieldoo/shieldoo-mesh-admin/utils"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

var cfg *utils.Config

func Init(encryptor utils.ModelEncyptorInterface) (*utils.Config, *gorm.DB) {
	log.SetLevel(log.InfoLevel)
	log.Info("Init shieldoo-mesh-admin")
	cfg = utils.Init()
	log.SetLevel(log.Level(cfg.Server.Loglevel))
	logdata, _ := json.Marshal(cfg)
	log.Debug("configdata: ", string(logdata))

	cfg.ModelEncyptor = encryptor

	if cfg.ModelEncyptor == nil {
		panic("ModelEncyptor plugin not found")
	}

	model.Init(cfg)
	graph.Init(cfg)
	myjwt.Init(cfg)
	authserver.Init(cfg)
	job.Init(cfg)

	return cfg, model.Connection()
}

func Run() {
	// check plugins before starting
	if cfg.Segment == nil {
		panic("Segment plugin not found")
	}
	if cfg.SecurityLogStore == nil {
		panic("SecurityLogStore plugin not found")
	}
	// emailing
	if cfg.Emailing == nil {
		panic("Emailing plugin not found")
	}

	if cfg.LogStore == nil {
		panic("LogStore plugin not found")
	}
	// set logstore
	logstore.PluginSecurityLogStore = cfg.SecurityLogStore
	logstore.PluginLogStore = cfg.LogStore

	app.Run(cfg)
}
