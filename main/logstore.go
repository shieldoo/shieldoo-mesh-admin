package main

import (
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/shieldoo/shieldoo-mesh-admin/logstore"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

var dbConn *gorm.DB

func LogInit() {
	dbConn = model.Connection()

	// migrate
	dbConn.AutoMigrate(&LogStoreSecurity{})
	dbConn.AutoMigrate(&LogStore{})

	// start cleaning job
	go LogCleanerJob()
}

type Base struct {
	ID int `gorm:"autoIncrement;primaryKey"`
}

type LogStoreSecurity struct {
	Base
	Data    string    `gorm:"type:JSONB NOT NULL DEFAULT '{}'::JSONB;index:,type:gin"`
	UPN     string    `gorm:"type:varchar(256);index;not null"`
	Created time.Time `gorm:"type:TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;index"`
}

type LogStore struct {
	Base
	Data     string    `gorm:"type:JSONB NOT NULL DEFAULT '{}'::JSONB;index:,type:gin"`
	UPN      string    `gorm:"type:varchar(256);index;not null"`
	AccessID int       `gorm:"null"`
	Created  time.Time `gorm:"type:TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;index"`
}

type MySecurityLogStore struct {
}

type MyLogStore struct {
}

type NebulaLogStore struct {
	Msg   string `json:"msg"`
	Level string `json:"level"`
	VpnIp string `json:"vpnIp"`
}

func (c MySecurityLogStore) Store(lgx *logstore.SecurityLogEntry) {
	data, err := json.Marshal(lgx)
	if err != nil {
		log.Error("security-log-entry json error: ", err)
	}

	e := LogStoreSecurity{
		UPN:     lgx.UPN,
		Created: lgx.Timestamp,
		Data:    string(data),
	}

	if result := dbConn.Create(&e); result.Error != nil {
		log.Error("DB error: ", result.Error)
		return
	}
}

func (c MySecurityLogStore) SearchSecLog(dest *[]logstore.LogStoreSecurity, upn string, dateFrom time.Time, dateTo time.Time, search string, maxrecords int) error {
	tx := dbConn.
		Order("created desc").
		Limit(maxrecords)

	tx = searchConditionUPN(tx, upn)
	tx = searchConditionTFrom(tx, dateFrom)
	tx = searchConditionTTo(tx, dateTo)
	tx = searchConditionSearch(tx, search)
	var ret []LogStoreSecurity
	if result := tx.Find(&ret); result.Error != nil {
		log.Error("DB error: ", result.Error)
		return result.Error
	}
	// map result
	for _, v := range ret {
		*dest = append(*dest, logstore.LogStoreSecurity{
			Base:    logstore.Base{ID: v.ID},
			UPN:     v.UPN,
			Data:    v.Data,
			Created: v.Created,
		})
	}

	return nil
}

func (c MyLogStore) Store(upn string, accessid int, dataarr string) {
	s := strings.Split(dataarr, "\n")
	for _, v := range s {
		if strings.HasPrefix(v, `{"`) {
			// try to parse log JSON
			var logx NebulaLogStore
			err := json.Unmarshal([]byte(v), &logx)
			if err != nil {
				log.Debug("logstore json error: ", err)
				continue
			}
			if (logx.Level == "info" &&
				(logx.Msg == "Handshake message sent" ||
					logx.Msg == "Goodbye" ||
					logx.Msg == "Handshake timed out" ||
					logx.Msg == "Attempt to relay through hosts" ||
					logx.Msg == "handleCreateRelayResponse" ||
					logx.Msg == "Client cert refreshed from disk" ||
					logx.Msg == "Tunnel status" ||
					logx.Msg == "Blocklisting cert")) ||
				(logx.Level == "error" &&
					(logx.Msg == "Failed to send handshake message" ||
						logx.Msg == "Failed to write outgoing packet" ||
						logx.Msg == "Failed to read packets")) {
				continue
			}
			e := LogStore{
				UPN:      upn,
				AccessID: accessid,
				Data:     v,
				Created:  time.Now().UTC(),
			}
			if result := dbConn.Create(&e); result.Error != nil {
				log.Error("DB error: ", result.Error)
			}
		}
	}
}
func (c MyLogStore) SearchLog(dest *[]logstore.LogStore, upn string, dateFrom time.Time, dateTo time.Time, search string, maxrecords int) error {
	tx := dbConn.
		Order("created desc").
		Limit(maxrecords)

	tx = searchConditionUPN(tx, upn)
	tx = searchConditionTFrom(tx, dateFrom)
	tx = searchConditionTTo(tx, dateTo)
	tx = searchConditionSearch(tx, search)
	var ret []LogStore
	if result := tx.Find(&ret); result.Error != nil {
		log.Error("DB error: ", result.Error)
		return result.Error
	}
	// map result
	for _, v := range ret {
		*dest = append(*dest, logstore.LogStore{
			Base:     logstore.Base{ID: v.ID},
			UPN:      v.UPN,
			AccessID: v.AccessID,
			Data:     v.Data,
			Created:  v.Created,
		})
	}
	return nil
}

//TODO: there can be also syntax CurrentObject.Certificate.ID=0
// "data"->'CurrentObject'->'Certificate'->>'ID'='0'

func searchConditionSearch(tx *gorm.DB, item string) *gorm.DB {
	items := strings.Split(item, ",")
	ret := tx
	for idx, i := range items {
		if i != "" {
			name := "n" + strconv.Itoa(idx)
			schar := ""
			soper := ""
			if strings.Contains(i, "=") {
				schar = "="
				soper = "="
			} else if strings.Contains(i, "~") {
				schar = "~"
				soper = "ilike"
			}
			if schar == "" {
				ret = ret.
					Where("data::text ilike @"+name, sql.Named(name, "%"+i+"%"))
			} else {
				cond := strings.Split(i, schar)
				objs := strings.Split(cond[0], ".")
				var sqlargs []interface{}
				_where := "data "
				for sidx, o := range objs {
					if (len(objs) - 1) == sidx {
						_where += " ->>"
					} else {
						_where += " ->"
					}
					_locname := name + "i" + strconv.Itoa(sidx)
					_where += " @" + _locname
					sqlargs = append(sqlargs, sql.Named(_locname, o))
				}
				_where += " " + soper + " @" + name
				_srch := cond[1]
				if schar == "~" {
					_srch = "%" + _srch + "%"
				}
				sqlargs = append(sqlargs, sql.Named(name, _srch))
				ret = ret.
					Where(_where, sqlargs...)
			}
		}
	}
	return ret
}

func searchConditionUPN(tx *gorm.DB, item string) *gorm.DB {
	if item != "" {
		return tx.
			Where("upn ilike @upn", sql.Named("upn", item))
	}
	return tx
}

func searchConditionTFrom(tx *gorm.DB, item time.Time) *gorm.DB {
	if !item.IsZero() {
		tx = tx.
			Where("created >= @tfrom", sql.Named("tfrom", item))
	}
	return tx
}

func searchConditionTTo(tx *gorm.DB, item time.Time) *gorm.DB {
	if !item.IsZero() {
		tx = tx.
			Where("created <= @tto", sql.Named("tto", item))
	}
	return tx
}

func CleanSecLog(days int64) {
	db := model.Connection()

	if result := db.Delete(LogStoreSecurity{}, "created < ?", time.Now().UTC().Add(time.Hour*(-24)*time.Duration(days))); result.Error != nil {
		log.Error("DB error: ", result.Error)
	}
}

func CleanLog(days int64) {
	db := model.Connection()

	if result := db.Delete(LogStore{}, "created < ?", time.Now().UTC().Add(time.Hour*(-24)*time.Duration(days))); result.Error != nil {
		log.Error("DB error: ", result.Error)
	}
}

func LogCleanerJob() {
	for {
		CleanSecLog(30)
		CleanLog(7)
		time.Sleep(time.Hour * 24)
	}
}
