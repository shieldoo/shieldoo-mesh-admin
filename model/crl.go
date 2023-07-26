package model

import (
	"encoding/json"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func CreateCRL(db *gorm.DB) {
	var ret []string

	key := "CRL"

	// delete old records
	db.Where("access_id is null and valid_to < ?", time.Now().UTC()).Delete(Certificate{})

	var c []Certificate
	result := db.Where("access_id is null and valid_to > ?", time.Now().UTC()).Find(&c)
	if result.Error != nil {
		log.Error(fmt.Sprintf("cannot generate CRL: %s", result.Error))
		return
	}

	for _, i := range c {
		ret = append(ret, i.Fingerprint)
	}

	b, err := json.Marshal(ret)
	if err != nil {
		log.Error(fmt.Sprintf("cannot generate CRL: %s", err))
		return
	}

	err = DacSaveKey(key, string(b))

	if err != nil {
		log.Error("Unable to connect to database: ", err)
	}
}

func DownloadCRL(db *gorm.DB) ([]string, error) {
	var ret []string

	key := "CRL"
	data, err := DacGetKey(key)
	if err != nil {
		return ret, err
	}

	err = json.Unmarshal([]byte(data), &ret)
	if err != nil {
		return ret, err
	}

	return ret, nil
}
