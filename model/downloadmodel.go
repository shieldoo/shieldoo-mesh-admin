package model

import (
	"fmt"

	"gopkg.in/yaml.v2"
	"gorm.io/gorm"
)

type NebulaClientYamlConfig struct {
	AccessId int    `yaml:"accessid"`
	PublicIP string `yaml:"publicip"`
	Uri      string `yaml:"uri"`
	Secret   string `yaml:"secret"`
}

type NebulaClientUPNYamlConfig struct {
	Upn    string `yaml:"upn"`
	Uri    string `yaml:"uri"`
	Secret string `yaml:"secret"`
}

type NebulaYamlConfigFW struct {
	Port   string   `yaml:"port"`
	Proto  string   `yaml:"proto"`
	Host   string   `yaml:"host,omitempty"`
	Groups []string `yaml:"groups,omitempty"`
}

type NebulaYamlConfig struct {
	Pki struct {
		Ca        string   `yaml:"ca"`
		Cert      string   `yaml:"cert"`
		Key       string   `yaml:"key"`
		Blocklist []string `yaml:"blocklist"`
	} `yaml:"pki"`
	StaticHostMap map[string][]string `yaml:"static_host_map"`
	Lighthouse    struct {
		AmLighthouse bool     `yaml:"am_lighthouse"`
		Interval     int      `yaml:"interval"`
		Hosts        []string `yaml:"hosts"`
	} `yaml:"lighthouse"`
	Listen struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"listen"`
	Punchy struct {
		Punch   bool `yaml:"punch"`
		Respond bool `yaml:"respond"`
	} `yaml:"punchy"`
	Relay struct {
		Relays    []string `yaml:"relays"`
		AmRelay   bool     `yaml:"am_relay"`
		UseRelays bool     `yaml:"use_relays"`
	} `yaml:"relay"`
	Tun struct {
		Disabled           bool        `yaml:"disabled"`
		Dev                string      `yaml:"dev"`
		DropLocalBroadcast bool        `yaml:"drop_local_broadcast"`
		DropMulticast      bool        `yaml:"drop_multicast"`
		TxQueue            int         `yaml:"tx_queue"`
		Mtu                int         `yaml:"mtu"`
		Routes             interface{} `yaml:"routes"`
		UnsafeRoutes       interface{} `yaml:"unsafe_routes"`
	} `yaml:"tun"`
	Logging struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"logging"`
	Firewall struct {
		Conntrack struct {
			TCPTimeout     string `yaml:"tcp_timeout"`
			UDPTimeout     string `yaml:"udp_timeout"`
			DefaultTimeout string `yaml:"default_timeout"`
			MaxConnections int    `yaml:"max_connections"`
		} `yaml:"conntrack"`
		Outbound []NebulaYamlConfigFW `yaml:"outbound"`
		Inbound  []NebulaYamlConfigFW `yaml:"inbound"`
	} `yaml:"firewall"`
}

func DownloadCreateNebulaConfig(db *gorm.DB, a *Access, isLighthouse bool, port int) (string, error) {
	n := NebulaYamlConfig{}
	var err error

	n.Pki.Ca = SystemConfig().CA.Crt

	n.Pki.Cert = a.Certificate.SecretCrt
	n.Pki.Key = a.Certificate.SecretKey

	n.Pki.Blocklist, err = DownloadCRL(db)
	if err != nil {
		return "", nil
	}

	n.Lighthouse.AmLighthouse = isLighthouse
	if isLighthouse {
		n.Listen.Host = "0.0.0.0"
		n.Listen.Port = port
	}

	n.Relay.AmRelay = isLighthouse
	n.Relay.UseRelays = false

	n.Lighthouse.Interval = 60
	for _, i := range SystemConfig().Lighthouses {
		n.Lighthouse.Hosts = append(n.Lighthouse.Hosts, i.Access.IpAddress)
	}

	n.Punchy.Punch = true
	if a.NebulaPunchBack != nil {
		n.Punchy.Respond = *a.NebulaPunchBack
	}

	n.Tun.Disabled = false
	if isLighthouse {
		n.Tun.Dev = "nebula-lh"
	} else {
		n.Tun.Dev = fmt.Sprintf("shd%d", a.ID)
	}
	n.Tun.DropLocalBroadcast = true
	n.Tun.DropMulticast = false
	n.Tun.TxQueue = 500
	n.Tun.Mtu = 1200

	n.Logging.Level = "info"
	n.Logging.Format = "json"

	n.Firewall.Conntrack.TCPTimeout = "12m"
	n.Firewall.Conntrack.UDPTimeout = "3m"
	n.Firewall.Conntrack.DefaultTimeout = "10m"
	n.Firewall.Conntrack.MaxConnections = 100000

	for _, i := range a.Fwconfig.Fwconfigouts {
		j := NebulaYamlConfigFW{Proto: i.Proto, Port: i.Port}
		if i.Host == "group" {
			for _, jgrp := range i.FwconfigGroups {
				j.Groups = append(j.Groups, jgrp.Group.Name)
			}
		} else {
			j.Host = i.Host
		}
		n.Firewall.Outbound = append(n.Firewall.Outbound, j)
	}
	for _, i := range a.Fwconfig.Fwconfigins {
		j := NebulaYamlConfigFW{Proto: i.Proto, Port: i.Port}
		if i.Host == "group" {
			for _, jgrp := range i.FwconfigGroups {
				j.Groups = append(j.Groups, jgrp.Group.Name)
			}
		} else {
			j.Host = i.Host
		}
		n.Firewall.Inbound = append(n.Firewall.Inbound, j)
	}

	n.StaticHostMap = make(map[string][]string)

	for _, i := range SystemConfig().Lighthouses {
		n.StaticHostMap[i.Access.IpAddress] = []string{i.PublicIP + ":" + fmt.Sprint(i.Port)}
		if !isLighthouse {
			n.Relay.Relays = append(n.Relay.Relays, i.Access.IpAddress)
		}
	}

	cs, err := yaml.Marshal(&n)
	return string(cs), err
}

func DownloadGenereateMyconfigUPN(cuser *Entity) (string, error) {
	usrcfg := NebulaClientUPNYamlConfig{
		Upn:    cuser.UPN,
		Uri:    _cfg.Server.URI + "/",
		Secret: cuser.Secret,
	}
	if csb, err := yaml.Marshal(&usrcfg); err == nil {
		return string(csb), err
	} else {
		return "", err
	}
}

func DownloadGenereateMyconfig(a *Access) (string, error) {
	usrcfg := NebulaClientYamlConfig{
		AccessId: a.ID,
		PublicIP: "",
		Uri:      _cfg.Server.URI + "/",
		Secret:   a.Secret,
	}
	if csb, err := yaml.Marshal(&usrcfg); err == nil {
		return string(csb), err
	} else {
		return "", err
	}
}
