package model

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/shieldoo/shieldoo-mesh-admin/utils"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var _cfg *utils.Config
var globsqlDB *gorm.DB

func TestInit(cfg *utils.Config) {
	_cfg = cfg
}

func Init(cfg *utils.Config) {
	_cfg = cfg

	newLogger := logger.New(
		log.New(), // io writer
		logger.Config{
			SlowThreshold:             time.Duration(_cfg.Database.Log.SlowQueryms * 1000000), // Slow SQL threshold
			LogLevel:                  logger.LogLevel(_cfg.Database.Log.LogLevel),            // Log level
			IgnoreRecordNotFoundError: _cfg.Database.Log.IgnoreRecordNotFound,                 // Ignore ErrRecordNotFound error for logger
			Colorful:                  _cfg.Database.Log.Colorful,                             // Disable color
		},
	)

	var err error
	globsqlDB, err = gorm.Open(postgres.Open(_cfg.Database.Url), &gorm.Config{Logger: newLogger})
	if err != nil {
		log.Panic("Unable to connect to database: ", err)
		os.Exit(100)
	}
	sqlDB, err := globsqlDB.DB()
	if err != nil {
		log.Panic("Unable to connect to database: ", err)
		os.Exit(100)
	}

	// SetMaxIdleConns sets the maximum number of connections in the idle connection pool.
	sqlDB.SetMaxIdleConns(2)

	// SetMaxOpenConns sets the maximum number of open connections to the database.
	sqlDB.SetMaxOpenConns(5)

	// SetConnMaxLifetime sets the maximum amount of time a connection may be reused.
	sqlDB.SetConnMaxLifetime(time.Minute)

	// inti DB structures
	log.Info("Migrate DB structures")
	db := Connection()

	db.AutoMigrate(
		&Entity{},
		&Group{},
		&UserAccessTemplate{},
		&UserAccessTemplateGroup{},
		&UserAccess{},
		&UserAccessGroup{},
		&Access{},
		&AccessGroup{},
		&Fwconfig{},
		&Fwconfigout{},
		&Fwconfigin{},
		&FwconfiginGroup{},
		&FwconfigoutGroup{},
		&Config{},
		&Certificate{},
		&Ipam{},
		&DBVersion{},
		&KeyValueStore{},
		&AccessListenerType{},
		&AccessListener{},
		&DeviceLogin{},
		&AccessStatistic{},
		&AccessDevice{},
		&AccessStatisticData{},
	)
	dbMigration(db)

	log.Info("Migrate DB structures - DONE")
	InitSystemConfig()
	dbCreateDefaultData(db)
}

func updateSequence(db *gorm.DB, sequence string) error {
	sql := fmt.Sprintf("SELECT COALESCE(nextval('%s')); ", sequence)
	if err := db.Exec(sql).Error; err != nil {
		log.Error("Unable to update sequence: ", err)
		return err
	}
	return nil
}

func dbCreateDefaultData(db *gorm.DB) {
	// populate default data

	// Default Firewall
	var fw Fwconfig
	if result := db.First(&fw, "id = ?", ENTITY_DEFAULTFIREWALL_ID); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			log.Debug("create default fwconfig")
			fw = Fwconfig{
				Base:    Base{ID: ENTITY_DEFAULTFIREWALL_ID},
				Name:    "default",
				Changed: time.Now().UTC(),
				Fwconfigouts: []Fwconfigout{
					{Port: "any", Proto: "any", Host: "any"},
				},
				Fwconfigins: []Fwconfigin{
					{Port: "any", Proto: "any", Host: "any"},
				},
			}
			db.Create(&fw)
			updateSequence(db, "fwconfigs_id_seq")
		}
	}

	// UserAccessTemplate
	var uat UserAccessTemplate
	if result := db.First(&uat, "id = ?", ENTITY_DEFAULTTEMPLATE_ID); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			log.Debug("create default fwconfig")
			var deleted bool = false
			uat = UserAccessTemplate{
				Base:        Base{ID: ENTITY_DEFAULTTEMPLATE_ID},
				Name:        "default",
				Description: "Default template",
				FwconfigID:  ENTITY_DEFAULTFIREWALL_ID,
				ValidFrom:   time.Now().UTC(),
				ValidTo:     systemConfig.CA.ValidTo,
				Deleted:     &deleted,
				Changed:     time.Now().UTC(),
			}
			db.Create(&uat)
			updateSequence(db, "user_access_templates_id_seq")
		}
	}

	// create admin user
	if _cfg.Auth.AdminUser != "" && !systemConfig.AADSyncConfig.Enabled {
		var u Entity
		if result := db.First(&u, "upn = ?", _cfg.Auth.AdminUser); result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				log.Debug("create admin user: ", _cfg.Auth.AdminUser)
				u = Entity{
					EntityType:  ENTITY_USER,
					UPN:         _cfg.Auth.AdminUser,
					Name:        _cfg.Auth.AdminUser,
					Origin:      "invited",
					Roles:       `["USER","ADMINISTRATOR"]`,
					Description: "",
				}
				var o Entity
				DacInviteUser(_cfg.Auth.AdminUser, ENTITY_DEFAULTTEMPLATE_ID, &u, &o)
				// send invitation email
				// go SendInvitationEmail(u.UPN)
			}
		}
	}

	// create data for AccessListenerTypes
	arrAccessListenerTypes := []AccessListenerType{
		{
			Base:  Base{ID: 1},
			Glyph: "other",
			Name:  "Other",
		},
		{
			Base:  Base{ID: 2},
			Glyph: "server",
			Name:  "Server",
		},
		{
			Base:  Base{ID: 3},
			Glyph: "printer",
			Name:  "Printer",
		},
		{
			Base:  Base{ID: 4},
			Glyph: "nas",
			Name:  "NAS (Network Attached Storage)",
		},
	}
	for _, v := range arrAccessListenerTypes {
		var alt AccessListenerType
		if result := db.First(&alt, "id = ?", v.ID); result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				log.Debug("create AccessListenerType item: ", v)
				db.Create(&v)
			}
		}
	}
}

func dbMigration(db *gorm.DB) {
	// migration special steps for each version
	//dbMigration_0_2_2(db)
}

/*
func dbMigration_0_2_2(db *gorm.DB) {
	var v DBVersion
	versionstring := "0.2.2"
	if result := db.First(&v, "version = ?", versionstring); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			log.Info("UPGRADING DB to ", versionstring)

			// process DB upgrades
			if result := db.Exec("UPDATE entities SET entity_type = 1 WHERE is_user IS TRUE"); result.Error == nil {
				// process DB upgrades
				if result := db.Exec("ALTER TABLE entities DROP COLUMN is_user"); result.Error != nil {
					log.Panic("Unable to connect to database: ", result.Error)
					os.Exit(100)
				}
			}

			// mark that upgrade was installed
			v = DBVersion{Version: versionstring}
			if result := db.Create(&v); result.Error != nil {
				log.Panic("Unable to connect to database: ", result.Error)
				os.Exit(100)
			}
		} else {
			log.Panic("Unable to connect to database: ", result.Error)
			os.Exit(100)
		}
	}
}
*/

func Connection() *gorm.DB {
	return globsqlDB
}

type DeviceLogin struct {
	Id         string `gorm:"type:varchar(64);index:,unique;not null"`
	UPN        string `gorm:"type:varchar(256);not null"`
	AccessData string
	Created    time.Time `gorm:"type:TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"`
}

type Base struct {
	ID int `gorm:"autoIncrement;primaryKey"`
}

type Fwconfig struct {
	Base
	Name         string        `gorm:"type:varchar(256);index:,unique,expression:lower(name);unique;not null"`
	Fwconfigouts []Fwconfigout `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Fwconfigins  []Fwconfigin  `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Changed      time.Time     `gorm:"type:TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"`
}

type Fwconfigout struct {
	Base           `json:"-"`
	FwconfigID     int                `gorm:"index;not null" json:"-"`
	Port           string             `gorm:"type:varchar(32);not null"`
	Proto          string             `gorm:"type:varchar(32);not null"`
	Host           string             `gorm:"type:varchar(256);not null"`
	FwconfigGroups []FwconfigoutGroup `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type Fwconfigin struct {
	Base           `json:"-"`
	FwconfigID     int               `gorm:"index;not null" json:"-"`
	Port           string            `gorm:"type:varchar(32);not null"`
	Proto          string            `gorm:"type:varchar(32);not null"`
	Host           string            `gorm:"type:varchar(256);not null"`
	FwconfigGroups []FwconfiginGroup `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type FwconfiginGroup struct {
	Base         `json:"-"`
	FwconfiginID int `gorm:"index;not null" json:"-"`
	GroupID      int `gorm:"not null" json:"-"`
	Group        Group
}

type FwconfigoutGroup struct {
	Base          `json:"-"`
	FwconfigoutID int `gorm:"index;not null" json:"-"`
	GroupID       int `gorm:"not null" json:"-"`
	Group         Group
}

type Group struct {
	Base
	Name        string `gorm:"type:varchar(256);index:,unique,expression:lower(name);unique;not null;check:name ~ '^[a-zA-Z0-9_.-]*$'"`
	Description string
	ObjectId    string `gorm:"type:varchar(64);index;null"`
}

type AccessListenerType struct {
	Base
	Glyph string `gorm:"type:varchar(64);not null"`
	Name  string `gorm:"type:varchar(256);not null"`
}

type UserAccessTemplateGroup struct {
	Base                 `json:"-"`
	UserAccessTemplateID int `gorm:"index;not null" json:"-"`
	GroupID              int `gorm:"index;not null" json:"-"`
	Group                Group
}

type UserAccessTemplate struct {
	Base
	Name                     string `gorm:"type:varchar(256);not null"`
	Description              string
	UserAccessTemplateGroups []UserAccessTemplateGroup `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	FwconfigID               int                       `gorm:"not null"`
	Fwconfig                 Fwconfig
	ValidFrom                time.Time
	ValidTo                  time.Time
	Changed                  time.Time    `gorm:"type:TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"`
	UserAccesses             []UserAccess `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Deleted                  *bool        `gorm:"default:false;not null"`
}

type UserAccessGroup struct {
	Base         `json:"-"`
	UserAccessID int `gorm:"index;not null" json:"-"`
	GroupID      int `gorm:"index;not null" json:"-"`
	Group        Group
}

type UserAccess struct {
	Base
	Name                 string `gorm:"type:varchar(256);not null"`
	Description          string
	UserAccessTemplateID int `gorm:"not null"`
	UserAccessTemplate   UserAccessTemplate
	UserAccessGroups     []UserAccessGroup `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	FwconfigID           int               `gorm:"not null"`
	Fwconfig             Fwconfig
	EntityID             int `gorm:"index;not null"`
	ValidFrom            time.Time
	ValidTo              time.Time
	Secret               string    `gorm:"type:varchar(256);null" json:"-"`
	Changed              time.Time `gorm:"type:TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"`
	Accesses             []Access  `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}

func (u *UserAccess) AfterFind(tx *gorm.DB) (err error) {
	log.Debug("useraccess afterfind")
	data, err := _cfg.ModelEncyptor.Decrypt(u.Secret)
	if err != nil {
		log.Error("useraccess afterfind error: ", err)
		return err
	}
	u.Secret = data
	return nil
}

func (u *UserAccess) BeforeSave(tx *gorm.DB) (err error) {
	log.Debug("useraccess beforesave")
	data, err := _cfg.ModelEncyptor.Encrypt(u.Secret)
	if err != nil {
		log.Error("useraccess beforesave error: ", err)
		return err
	}
	u.Secret = data
	return nil
}

type AccessGroup struct {
	Base     `json:"-"`
	AccessID int `gorm:"index;not null" json:"-"`
	GroupID  int `gorm:"index;not null" json:"-"`
	Group    Group
}

type AccessListener struct {
	Base                 `json:"-"`
	AccessID             int `gorm:"index;not null" json:"-"`
	ListenPort           int
	Protocol             string
	ForwardPort          int
	ForwardHost          string
	AccessListenerTypeID int `gorm:"not null;default:1"`
	AccessListenerType   AccessListenerType
	Description          string
}

type Access struct {
	Base
	Name                     string `gorm:"type:varchar(256);not null"`
	IpAddress                string `gorm:"type:varchar(32);index;unique;not null"`
	FQDN                     string `gorm:"type:varchar(256);not null"`
	Description              string
	AccessGroups             []AccessGroup `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	FwconfigID               int           `gorm:"not null"`
	Fwconfig                 Fwconfig
	EntityID                 int `gorm:"index;not null"`
	ValidFrom                time.Time
	ValidTo                  time.Time
	Certificate              Certificate      `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;" json:",omitempty"`
	Secret                   string           `gorm:"type:varchar(256);null" json:"-"`
	Changed                  time.Time        `gorm:"type:TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"`
	AccessListeners          []AccessListener `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	NebulaPunchBack          *bool            `gorm:"default:false;not null"`
	NebulaRestrictiveNetwork *bool            `gorm:"default:false;not null"`
	Autoupdate               *bool            `gorm:"default:false;not null"`
	AccessStatistic          AccessStatistic  `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:",omitempty"`
	AccessDevice             AccessDevice     `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:",omitempty"`
	UserAccessID             int              `gorm:"index;null"`
	OSAutoupdateConfig       string
}

func (a *Access) AfterFind(tx *gorm.DB) (err error) {
	log.Debug("access afterfind")
	data, err := _cfg.ModelEncyptor.Decrypt(a.Secret)
	if err != nil {
		log.Error("access afterfind error: ", err)
		return err
	}
	a.Secret = data
	return nil
}

func (a *Access) BeforeSave(tx *gorm.DB) (err error) {
	log.Debug("access beforesave")
	data, err := _cfg.ModelEncyptor.Encrypt(a.Secret)
	if err != nil {
		log.Error("access beforesave error: ", err)
		return err
	}
	a.Secret = data
	return nil
}

type OSAutoupdateConfigType struct {
	Enabled                   bool `json:"enabled"`
	SecurityAutoupdateEnabled bool `json:"securityAutoupdateEnabled"`
	AllAutoupdateEnabled      bool `json:"allAutoupdateEnabled"`
	RestartAfterUpdate        bool `json:"restartAfterUpdate"`
	// 0 means any hour in day
	UpdateHour int `json:"updateHour"`
}

type AccessStatistic struct {
	AccessID                 int       `gorm:"primaryKey;not null"`
	IsConnected              *bool     `gorm:"default:false;not null"`
	NebulaRestrictiveNetwork *bool     `gorm:"default:false;not null"`
	Contacted                time.Time `gorm:"type:TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"`
}

type AccessStatisticData struct {
	ID          string `gorm:"type:varchar(256);primaryKey;not null"`
	HourPeriod  string `gorm:"type:varchar(16);index;not null"`
	UPN         string `gorm:"type:varchar(256);index;not null"`
	AccessID    int    `gorm:"not null"`
	IsConnected *bool  `gorm:"default:false;not null"`
	IsContacted *bool  `gorm:"default:false;not null"`
	DataIn      int64  `gorm:"default:0;not null"`
	DataOut     int64  `gorm:"default:0;not null"`
	IsUser      *bool  `gorm:"default:false;not null"`
}

type AccessDevice struct {
	AccessID      int       `gorm:"primaryKey;not null"`
	DeviceName    string    `gorm:"type:varchar(256);not null"`
	DeviceID      string    `gorm:"type:varchar(64);not null;index"`
	DeviceOs      string    `gorm:"type:varchar(256);not null"`
	ClientVersion string    `gorm:"type:varchar(256)"`
	Contacted     time.Time `gorm:"type:TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"`
	OSAutoUpdate  string
}

type OSAutoUpdateType struct {
	Type                 string    `json:"type"`
	Name                 string    `json:"name"`
	Version              string    `json:"version"`
	Description          string    `json:"description"`
	LastUpdate           time.Time `json:"last_update"`
	LastUpdateOutput     string    `json:"last_update_output"`
	Success              bool      `json:"success"`
	SecurityUpdatesCount int       `json:"security_updates_count"`
	OtherUpdatesCount    int       `json:"other_updates_count"`
	SecurityUpdates      []string  `json:"security_updates"`
	OtherUpdates         []string  `json:"other_updates"`
}

type Certificate struct {
	Base
	AccessID        int `gorm:"index;null"`
	SecretCrt       string
	SecretKey       string
	SecretPublicKey string
	Metadata        string
	Fingerprint     string `gorm:"type:varchar(256);not null"`
	ValidFrom       time.Time
	ValidTo         time.Time
}

type KeyValueStore struct {
	ID      string `gorm:"primaryKey;type:varchar(64);not null"`
	Data    string
	Changed time.Time `gorm:"type:TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"`
}

const (
	ENTITY_SERVER             = 0
	ENTITY_USER               = 1
	ENTITY_APPLIANCE          = 2
	ENTITY_DEFAULTTEMPLATE_ID = 1
	ENTITY_DEFAULTFIREWALL_ID = 1
)

// define roles in system
const (
	ROLE_SYSTEM        = "SYSTEM"
	ROLE_ADMINISTRATOR = "ADMINISTRATOR"
	ROLE_USER          = "USER"
)

type Entity struct {
	Base
	EntityType   int    `gorm:"type:int8 NOT NULL DEFAULT 0"`
	UPN          string `gorm:"type:varchar(256);index:,unique,expression:lower(upn);unique;not null"`
	Name         string `gorm:"type:varchar(256);index;not null"`
	Origin       string
	Roles        string
	Description  string
	Secret       string `gorm:"type:varchar(256) NOT NULL DEFAULT concat(md5(random()::text),md5(random()::text),md5(random()::text),md5(random()::text))" json:"-"`
	Accesses     []Access
	UserAccesses []UserAccess
}

func (e *Entity) AfterFind(tx *gorm.DB) (err error) {
	log.Debug("entity afterfind")
	data, err := _cfg.ModelEncyptor.Decrypt(e.Secret)
	if err != nil {
		log.Error("entity afterfind error: ", err)
		return err
	}
	e.Secret = data
	return nil
}

func (e *Entity) BeforeSave(tx *gorm.DB) (err error) {
	log.Debug("entity beforesave")
	data, err := _cfg.ModelEncyptor.Encrypt(e.Secret)
	if err != nil {
		log.Error("entity beforesave error: ", err)
		return err
	}
	e.Secret = data
	return nil
}

type Ipam struct {
	Base
	IPNumber int    `gorm:"index;unique;not null"`
	IP       string `gorm:"index;unique;not null"`
}

type DBVersion struct {
	Version string `gorm:"index;unique;not null"`
}
