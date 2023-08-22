package utils

import (
	"os"
	"strconv"

	"github.com/kelseyhightower/envconfig"
	"github.com/shieldoo/shieldoo-mesh-admin/logstore"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type ConfigLighthouse struct {
	Port    int    `yaml:"port"`
	Address string `yaml:"address"`
}

type ShieldooConf struct {
	TenantId string `yaml:"tenantid", envconfig:"AUTH_SHIELDOO_TENANTID"`
}

type Config struct {
	Server struct {
		Port            string   `yaml:"port", envconfig:"PORT"`
		Loglevel        int      `yaml:"loglevel", envconfig:"LOGLEVEL"`
		URI             string   `yaml:"uri", envconfig:"URI"`
		JobAPIKey       string   `yaml:"jobapikey", envconfig:"JOBAPIKEY"`
		WebSocketUrl    string   `yaml:"websocketurl", envconfig:"WEBSOCKETURL"`
		WebSocketIPs    []string `yaml:"websocketips", envconfig:"WEBSOCKETIPS"`
		StoreHeartBeats bool     `yaml:"store_heartbeats", envconfig:"STORE_HEARTBEATS"`
	} `yaml:"server"`
	OAuthServer struct {
		Secret   string `yaml:"secret", envconfig:"SECRET"`
		Duration int    `yaml:"duration", envconfig:"DURATION"`
	} `yaml:"oauthserver"`
	Auth struct {
		Issuer         string       `yaml:"issuer", envconfig:"AUTH_ISSUER"`
		InternalIssuer string       `yaml:"internal_issuer", envconfig:"AUTH_INTERNALISSUER"`
		Audience       []string     `yaml:"audience", envconfig:"AUTH_AUDIENCE"`
		AuthorizeUrl   string       `yaml:"authorize_url", envconfig:"AUTH_AUTHORIZEURL"`
		CallbackUrl    string       `yaml:"callback_url", envconfig:"AUTH_CALLBACKURL"`
		Shieldoo       ShieldooConf `yaml:"shieldoo", envconfig:"AUTH_SHIELDOO"`
		AdminUser      string       `yaml:"admin_user", envconfig:"AUTH_ADMINUSER"`
	} `yaml:"auth"`
	Database struct {
		Url        string `yaml:"url", envconfig:"URL"`
		MaxRecords int    `yaml:"maxrecords", envconfig:"MAXRECORDS"`
		Log        struct {
			LogLevel             int  `yaml:"loglevel"`
			SlowQueryms          int  `yaml:"slowqueryms"`
			IgnoreRecordNotFound bool `yaml:"ignorerecordnotfound"`
			Colorful             bool `yaml:"colorful"`
		}
	} `yaml:"database"`
	Lighthouses struct {
		MaxLighthouses int                `yaml:"maxlighthouses", envconfig:"MAXLIGHTHOUSES"`
		Secret         string             `yaml:"secret", envconfig:"SECRET"`
		InstancesMap   map[string]string  `envconfig:"INSTANCESMAP"`
		Instances      []ConfigLighthouse `yaml:"instances"`
	} `yaml:"lighthouses"`
	CostManagement struct {
		MonthPrice float64 `yaml:"monthprice", envconfig:"MONTHPRICE"`
		HourPrice  float64 `yaml:"hourprice", envconfig:"HOURPRICE"`
	} `yaml:"costmanagement"`
	// external plugins
	Segment          SegmentEventInterface              `yaml:"-"`
	SecurityLogStore logstore.SecurityLogStoreInterface `yaml:"-"`
	LogStore         logstore.LogStoreInterface         `yaml:"-"`
	ModelEncyptor    ModelEncyptorInterface             `yaml:"-"`
	Emailing         EmailInterface                     `yaml:"-"`
}

var cfg Config

func Init() *Config {
	readFile(&cfg)
	readEnv(&cfg)

	// check instance map
	if len(cfg.Lighthouses.InstancesMap) > 0 {
		cfg.Lighthouses.Instances = []ConfigLighthouse{}
		for k, e := range cfg.Lighthouses.InstancesMap {
			p, _ := strconv.Atoi(e)
			cfg.Lighthouses.Instances = append(cfg.Lighthouses.Instances, ConfigLighthouse{Address: k, Port: p})
		}
	}

	log.Debug("App config:")
	log.Debug(cfg)
	return &cfg
}

func processError(err error) {
	log.Error(err)
}

func readFile(mycfg *Config) {
	f, err := os.Open("config.yaml")
	if err != nil {
		processError(err)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(mycfg)
	if err != nil {
		processError(err)
	}
}

func readEnv(mycfg *Config) {
	err := envconfig.Process("", mycfg)
	if err != nil {
		processError(err)
	}
}
