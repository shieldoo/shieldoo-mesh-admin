package model

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/shieldoo/shieldoo-mesh-admin/ncert"
	"github.com/shieldoo/shieldoo-mesh-admin/utils"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type LighthouseConfig struct {
	PublicIP string
	Port     int
	Access   Access
	Hash     string
}

type AADSyncConfig struct {
	Enabled         bool
	AADTenantID     string
	AADClientID     string
	AADClientSecret string
	AdminGroupID    string
}

type CliApiConfig struct {
	Enabled bool
	ApiKey  string
}

type SystemConfigDef struct {
	CA struct {
		Crt     string
		ValidTo time.Time
	}
	Network struct {
		CIDR           string
		MaxLighthouses int
	}
	Lighthouses   []LighthouseConfig
	Secret        string
	AADSyncConfig AADSyncConfig
	CliApiConfig  CliApiConfig
}

var systemConfig SystemConfigDef
var systemConfigTimestamp time.Time = time.Now().UTC()

func SystemConfig() *SystemConfigDef {
	if systemConfigTimestamp.Add(30 * time.Second).Before(time.Now().UTC()) {
		loadSystemConfig()
		log.Debug("system config loaded from DB")
		systemConfigTimestamp = time.Now().UTC()
	}
	return &systemConfig
}

func (m SystemConfigDef) GetCIDRMask() string {
	re := regexp.MustCompile(`(\/\d{1,2})`)
	ret := re.FindAllString(m.Network.CIDR, -1)
	if len(ret) == 1 {
		return ret[0]
	} else {
		return ""
	}
}

func (m SystemConfigDef) GetCIDR() string {
	return m.Network.CIDR
}

func (m SystemConfigDef) GetMaxLighthouses() int {
	return m.Network.MaxLighthouses
}

func SystemConfigApplyAadSyncConfig(aadSyncConfig AADSyncConfig) error {
	db := Connection()
	if merr := db.Transaction(func(tx *gorm.DB) error {
		var err error
		systemConfig.AADSyncConfig = aadSyncConfig
		err = systemConfig.Save(tx, true)
		return err
	}); merr != nil {
		return dacProcessError(merr)
	}
	return nil
}

func SystemConfigApplyCliApiConfig(enableApi bool) error {
	db := Connection()
	if merr := db.Transaction(func(tx *gorm.DB) error {
		var err error
		systemConfig.CliApiConfig.Enabled = enableApi
		if enableApi {
			systemConfig.CliApiConfig.ApiKey = utils.GenerateRandomString(64)
		} else {
			systemConfig.CliApiConfig.ApiKey = ""
		}
		err = systemConfig.Save(tx, true)
		return err
	}); merr != nil {
		return dacProcessError(merr)
	}
	return nil
}

func SystemConfigApplyCIDR(cidr string) error {

	// check cidr regex
	re := regexp.MustCompile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([1-2][0-9]|3[0-2]))$`)
	if !re.MatchString(cidr) {
		return errors.New("cidr is not valid")
	}

	//get attributes
	if systemConfig.Network.CIDR != cidr {
		db := Connection()
		if merr := db.Transaction(func(tx *gorm.DB) error {
			var err error
			systemConfig.Network.CIDR = cidr
			err = systemConfig.Save(tx, true)
			if err != nil {
				return err
			}
			//run there complex task which will readress all configured accesses and lighthouses
			err = SystemConfigMigrateCIDR(tx)
			return err
		}); merr != nil {
			return dacProcessError(merr)
		}
		// change CRL
		go CreateCRL(db)
		// recreate DNS
		go CreateDNS(db)
	}
	return nil
}

type Config struct {
	Key  string `gorm:"type:varchar(32);primaryKey;not null"`
	Data string
}

func (c *Config) AfterFind(tx *gorm.DB) (err error) {
	log.Debug("config after find - decrypting")
	data, err := _cfg.ModelEncyptor.Decrypt(c.Data)
	if err != nil {
		log.Error("config decrypt error: ", err)
		return err
	}
	c.Data = data
	return nil
}

func (c *Config) BeforeSave(tx *gorm.DB) (err error) {
	log.Debug("config before save - encrypting")
	data, err := _cfg.ModelEncyptor.Encrypt(c.Data)
	if err != nil {
		log.Error("config encrypt error: ", err)
		return err
	}
	c.Data = data
	return nil
}

func GetLighthouseIP(cidrnet string, maxl int, num int) string {
	if num < 1 || num > maxl {
		return ""
	}

	_, actualcidr, _ := net.ParseCIDR(cidrnet)
	lh, err := cidr.Host(actualcidr, num)

	if err == nil {
		return lh.String()
	} else {
		return ""
	}
}

func getHost(base *net.IPNet, num int) net.IP {
	ip, err := cidr.Host(base, num)
	if err != nil {
		panic(err)
	}
	return ip
}

func (c SystemConfigDef) Save(tx *gorm.DB, gencerts bool) error {

	if gencerts {
		var err error
		var subnets []string = []string{
			"0.0.0.0/5",
			"8.0.0.0/7",
			"11.0.0.0/8",
			"12.0.0.0/6",
			"16.0.0.0/4",
			"32.0.0.0/3",
			"64.0.0.0/2",
			"128.0.0.0/3",
			"160.0.0.0/5",
			"168.0.0.0/6",
			"172.0.0.0/12",
			"172.32.0.0/11",
			"172.64.0.0/10",
			"172.128.0.0/9",
			"173.0.0.0/8",
			"174.0.0.0/7",
			"176.0.0.0/4",
			"192.0.0.0/9",
			"192.128.0.0/11",
			"192.160.0.0/13",
			"192.169.0.0/16",
			"192.170.0.0/15",
			"192.172.0.0/14",
			"192.176.0.0/12",
			"192.192.0.0/10",
			"193.0.0.0/8",
			"194.0.0.0/7",
			"196.0.0.0/6",
			"200.0.0.0/5",
			"208.0.0.0/4",
			"224.0.0.0/3",
		}
		// update IDs for access and create certificates
		for i := 0; i < len(c.Lighthouses); i++ {
			c.Lighthouses[i].Access.Base.ID = i
			c.Lighthouses[i].Access.Name = fmt.Sprintf("lighthouse-%s:%d", c.Lighthouses[i].PublicIP, c.Lighthouses[i].Port)
			c.Lighthouses[i].Access.ValidTo = systemConfig.CA.ValidTo

			// create firewall
			c.Lighthouses[i].Access.Fwconfig = Fwconfig{
				Name:         "lighthouse",
				Changed:      time.Now().UTC(),
				Fwconfigouts: []Fwconfigout{{Proto: "any", Port: "any", Host: "any"}},
				Fwconfigins:  []Fwconfigin{{Proto: "icmp", Port: "any", Host: "any"}, {Proto: "tcp", Port: "80", Host: "any"}, {Proto: "udp", Port: "53", Host: "any"}},
			}

			// generate IP address
			c.Lighthouses[i].Access.IpAddress = GetLighthouseIP(c.Network.CIDR, c.Network.MaxLighthouses, i+1)

			c.Lighthouses[i].Access.Certificate, err = CreateCert(tx, &(c.Lighthouses[i].Access), c.Lighthouses[i].Access.Name, subnets, "")
			if err != nil {
				log.Error("CERT error1: ", err)
				return err
			}

			//generate hash for config
			c.Lighthouses[i].Hash = ""
			result, _ := json.Marshal(c.Lighthouses[i])
			log.Debug("Lighthouse hash data: ", string(result))
			hash := sha256.Sum256(result)
			hashstr := base64.URLEncoding.EncodeToString(hash[:])
			log.Debug("Lighthouse hash: ", hashstr)
			c.Lighthouses[i].Hash = hashstr
		}
	}

	j, jerr := json.Marshal(c)
	if jerr == nil {
		cfg := Config{Key: "SYSTEM", Data: string(j)}
		err := saveConfig(tx, &cfg)
		return err
	} else {
		log.Error("JSON error: ", jerr)
		return jerr
	}
}

func saveConfig(tx *gorm.DB, cfg *Config) error {
	var c Config
	if result := tx.First(&c, "key = ?", cfg.Key); result.Error != nil {
		log.Debug("Create config")
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			r := tx.Create(&cfg)
			if r.Error != nil {
				log.Error("DB error2: ", r.Error)
				return r.Error
			}
		} else {
			log.Error("DB error3: ", result.Error)
			return result.Error
		}
	} else {
		c.Data = cfg.Data
		if result := tx.Save(&c); result.Error != nil {
			log.Error("DB error4: ", result.Error)
			return result.Error
		}
	}
	return nil
}

func InitSystemConfig() {

	regenCerts := false
	regenAllCerts := false

	// load config from DB or defaults
	loadSystemConfig()

	log.Info("Loading system config ...")

	// load CA certs
	ca, crt, err := ncert.GetCACert()
	if err != nil {
		log.Panic("CA CER error: ", err)
		os.Exit(102)
	}
	log.Debug("Config CA valid to: ", systemConfig.CA.ValidTo)
	log.Debug("CA valid to: ", ca.Details.Notafter)
	systemConfig.CA.Crt = crt
	if systemConfig.CA.ValidTo != ca.Details.Notafter {
		log.Info("CA cert changed, config will be reloaded")
		regenCerts = true
		regenAllCerts = true
	}
	systemConfig.CA.ValidTo = ca.Details.Notafter

	// load secrets
	systemConfig.Secret = _cfg.Lighthouses.Secret
	systemConfig.Network.MaxLighthouses = _cfg.Lighthouses.MaxLighthouses

	// #### load lighthouses
	var newL []LighthouseConfig
	// delete unused lighthouses
	for _, l := range systemConfig.Lighthouses {
		_f := false
		for _, nl := range _cfg.Lighthouses.Instances {
			if nl.Address == l.PublicIP && nl.Port == l.Port {
				_f = true
				break
			}
		}
		if _f {
			newL = append(newL, l)
		} else {
			// there is change in lighthouse configuration
			regenCerts = true
		}
	}
	// create new lighthouses
	for _, nl := range _cfg.Lighthouses.Instances {
		_f := false
		for _, l := range newL {
			if nl.Address == l.PublicIP && nl.Port == l.Port {
				_f = true
				break
			}
		}
		if !_f {
			regenCerts = true
			_n := LighthouseConfig{
				PublicIP: nl.Address,
				Port:     nl.Port,
			}
			newL = append(newL, _n)
		}
	}
	systemConfig.Lighthouses = newL
	// save changes - and if needed regenerate lighthouses metadata and certs
	db := Connection()
	systemConfig.Save(db, regenCerts)
	if regenAllCerts {
		log.Info("All certs must be regenerated")
		if merr := db.Transaction(func(tx *gorm.DB) error {
			//run there complex task which will readress all configured accesses and lighthouses
			return SystemConfigMigrateCIDR(tx)
		}); merr != nil {
			return
		}
		// change CRL
		go CreateCRL(db)
		// recreate DNS
		go CreateDNS(db)
	}
}

func loadSystemConfig() {
	db := Connection()
	var c Config
	if result := db.First(&c, "key = ?", "SYSTEM"); result.Error != nil {
		// DEFAULTS
		systemConfig.Network.CIDR = "100.127.192.0/18"
		systemConfig.Network.MaxLighthouses = 4
	}
	json.Unmarshal([]byte(c.Data), &systemConfig)
	log.Debug("SystemConfig loaded: ", c.Data)

	// update IP addresses for WSS
	go netutilsConfigureWSSIPs()
}

func netutilsConfigureWSSIPs() {
	// update IP addresses for WSS
	fqdn := strings.Replace(strings.Replace(_cfg.Server.WebSocketUrl, "wss:", "", -1), "/", "", -1)
	arr, err := netutilsResolveDNS(fqdn)
	if err == nil && len(arr) > 0 {
		log.Debug("set new IPs for WSS: ", arr)
		_cfg.Server.WebSocketIPs = arr
	}
}

func netutilsResolveDNS(fqdn string) ([]string, error) {
	fqdn = strings.TrimSpace(fqdn)
	ips, err := net.LookupIP(fqdn)
	if err != nil {
		log.Error("dns A resolve error: ", err)
		return []string{}, err
	}
	var ret []string
	for _, i := range ips {
		ret = append(ret, i.String())
	}
	return ret, nil
}

func SystemConfigMigrateCIDR(tx *gorm.DB) error {
	// delete all ipams
	if dbresult := tx.Exec("DELETE FROM ipams"); dbresult.Error != nil {
		log.Error("DB error: ", dbresult.Error)
		return dbresult.Error
	}

	// update all accesses - avoid IP address conflict
	if dbresult := tx.Exec("UPDATE accesses SET ip_address=id"); dbresult.Error != nil {
		log.Error("DB error: ", dbresult.Error)
		return dbresult.Error
	}

	var result []int

	if dbresult := tx.Raw("select id from accesses").Scan(&result); dbresult.Error != nil {
		log.Error("DB error: ", dbresult.Error)
		return dbresult.Error
	}
	for _, id := range result {
		var dest Access
		var err error
		// update IP address
		_, err = AcquireIP(tx, &dest, nil, false)
		if err == nil {
			if dbresult := tx.Model(&Access{}).Where("id = ?", id).Update("ip_address", dest.IpAddress); dbresult.Error != nil {
				log.Error("DB error: ", dbresult.Error)
				return dbresult.Error
			}
		}
		// ### generate new cert
		dest, err = dacAccessGet(tx, id)
		if err != nil {
			log.Error("DB error: ", err)
			return err
		}
		if dbresult := tx.Model(&Certificate{}).Where("access_id = ?", id).Update("access_id", nil); dbresult.Error != nil {
			log.Error("DB error: ", dbresult.Error)
			return dbresult.Error
		}
		dest.Certificate = Certificate{}
		//TODO - migrate certs with public key from old cert
		dest.Certificate, err = CreateCertAccess(tx, &dest, "")
		if err != nil {
			log.Debug("Ignoring cert creation", err)
			return err
		} else {
			if dbresult := tx.Create(&dest.Certificate); dbresult.Error != nil {
				log.Error("DB error: ", dbresult.Error)
				return dbresult.Error
			}
		}
	}
	// update access changed column
	if dbresult := tx.Model(&Access{}).Where("1 = 1").Update("changed", time.Now().UTC()); dbresult.Error != nil {
		log.Error("DB error: ", dbresult.Error)
		return dbresult.Error
	}
	return nil
}
