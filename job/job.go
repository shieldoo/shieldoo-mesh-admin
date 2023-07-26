package job

import (
	"math/rand"
	"time"

	"github.com/shieldoo/shieldoo-mesh-admin/model"
	"github.com/shieldoo/shieldoo-mesh-admin/utils"
	log "github.com/sirupsen/logrus"
)

var _cfg *utils.Config
var nextJobRunTime int

func Init(cfg *utils.Config) {
	_cfg = cfg
	rand.Seed(time.Now().UnixNano())
	nextJobRunTime = rand.Intn(300)
	log.Debug("JOB: next job run in ", nextJobRunTime, " seconds")
	go runJob()
	go aadJob()
}

func runJob() {
	for {
		time.Sleep(time.Duration(nextJobRunTime) * time.Second)
		log.Info("JOB: run jobs")
		jobapiCleanStats()
		nextJobRunTime = rand.Intn(24 * 60 * 60)
		log.Debug("JOB: next job run in ", nextJobRunTime, " seconds")
	}
}

func jobapiCleanStats() {
	log.Info("JOB: clean stats")
	go model.DacCleanDeviceLog()
	go model.DacCleanAccessStats()
}
