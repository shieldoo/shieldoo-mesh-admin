package logstore

import (
	"time"
)

const (
	LOGTYPE_INFO            string = "info"
	LOGTYPE_WARNING         string = "warning"
	LOGTYPE_ERROR           string = "error"
	LOGTYPE_LOGIN           string = "login"
	LOGTYPE_USERDEVICELOGIN string = "userdevicelogin"
	LOGTYPE_DEVICELOGIN     string = "devicelogin"
	LOGTYPE_DATAUPDATE      string = "dataupdate"
	LOGTYPE_DATAINSERT      string = "datainsert"
	LOGTYPE_DATADELETE      string = "datadelete"
)

type Base struct {
	ID int `gorm:"autoIncrement;primaryKey"`
}

type LogStoreSecurity struct {
	Base
	Data    string
	UPN     string
	Created time.Time
}

type LogStore struct {
	Base
	Data     string
	UPN      string
	AccessID int
	Created  time.Time
}

type SecurityLogStoreInterface interface {
	Store(data *SecurityLogEntry)
	SearchSecLog(dest *[]LogStoreSecurity, upn string, dateFrom time.Time, dateTo time.Time, search string, maxrecords int) error
}

type LogStoreInterface interface {
	Store(upn string, accessid int, dataarr string)
	SearchLog(dest *[]LogStore, upn string, dateFrom time.Time, dateTo time.Time, search string, maxrecords int) error
}

var PluginSecurityLogStore SecurityLogStoreInterface
var PluginLogStore LogStoreInterface

type SecurityLogEntry struct {
	LogType        string
	UPN            string
	Timestamp      time.Time
	Message        string
	Entity         string
	CurrentObject  interface{}
	OriginalObject interface{}
}

func (lgx *SecurityLogEntry) Store() {
	PluginSecurityLogStore.Store(lgx)
}

func LogItemStore(upn string, accessid int, dataarr string) {
	PluginLogStore.Store(upn, accessid, dataarr)
}

func SearchLog(dest *[]LogStore, upn string, dateFrom time.Time, dateTo time.Time, search string, maxrecords int) error {
	return PluginLogStore.SearchLog(dest, upn, dateFrom, dateTo, search, maxrecords)
}

func SearchSecLog(dest *[]LogStoreSecurity, upn string, dateFrom time.Time, dateTo time.Time, search string, maxrecords int) error {
	return PluginSecurityLogStore.SearchSecLog(dest, upn, dateFrom, dateTo, search, maxrecords)
}
