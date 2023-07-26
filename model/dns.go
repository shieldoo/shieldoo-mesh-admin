package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func CreateDNS(db *gorm.DB) {
	var ret []string

	var c []Access
	result := db.Where("fqdn <> ''").Find(&c)
	if result.Error != nil {
		log.Error(fmt.Sprintf("cannot generate DNS: %s", result.Error))
		return
	}

	for _, i := range c {
		ret = append(ret, i.IpAddress+" "+i.FQDN)
	}

	b, err := json.Marshal(ret)
	if err != nil {
		log.Error(fmt.Sprintf("cannot generate DNS: %s", result.Error))
		return
	}

	sdns := string(b)

	// check if there is change
	var k KeyValueStore
	result = db.Where("id = ?", "DNS").First(&k)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			log.Info("creating DNS records ..")
		} else {
			log.Error("Unable to connect to database: ", result.Error)
			return
		}
	}

	if k.Data == sdns {
		log.Debug("DNS database not changed.")
	}

	log.Debug("DNS database changed - saving")
	kvdef := KeyValueStore{ID: "DNS", Data: sdns, Changed: time.Now().UTC()}
	if result := db.Save(&kvdef); result.Error != nil {
		log.Error("Unable to connect to database: ", result.Error)
	}
}

func DownloadDNS(db *gorm.DB) ([]string, error) {
	var ret []string

	var c KeyValueStore
	result := db.Where("id = ?", "DNS").First(&c)
	if result.Error != nil {
		return ret, result.Error
	}

	err := json.Unmarshal([]byte(c.Data), &ret)
	if result.Error != nil {
		return ret, err
	}

	return ret, nil
}
