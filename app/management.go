package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/shieldoo/shieldoo-mesh-admin/logstore"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type ManagementConnectionStatistics struct {
	UPN                     string    `json:"upn"`
	VpnIP                   string    `json:"vpnIp"`
	Level                   string    `json:"level"`
	Time                    time.Time `json:"time"`
	IsConnected             bool      `json:"isConnected"`
	IsOverRestrictedNetwork bool      `json:"isOverRestrictedNetwork"`
}

type ManagementOSAutoupdateRequest struct {
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

type ManagementRequest struct {
	AccessID      int       `json:"access_id"`
	ConfigHash    string    `json:"confighash"`
	DnsHash       string    `json:"dnshash"`
	Timestamp     time.Time `json:"timestamp"`
	LogData       string    `json:"log_data"`
	IsConnected   bool      `json:"is_connected"`
	OverWebSocket bool      `json:"over_websocket"`
}

type ManagementResponseConfigData struct {
	Data      string `json:"config"`
	Hash      string `json:"hash"`
	IPAddress string `json:"ipaddress"`
}

type ManagementResponseConfig struct {
	AccessID                  int                                  `json:"accessid"`
	Name                      string                               `json:"name"`
	UPN                       string                               `json:"upn"`
	ConfigData                ManagementResponseConfigData         `json:"config"`
	NebulaPunchBack           bool                                 `json:"nebulapunchback"`
	NebulaRestrictiveNetwork  bool                                 `json:"nebularestrictivenetwork"`
	Autoupdate                bool                                 `json:"autoupdate"`
	WebSocketUrl              string                               `json:"websocketurl"`
	WebSocketIPs              []string                             `json:"websocketips"`
	WebSocketUsernamePassword string                               `json:"websocketusernamepassword"`
	ApplianceListeners        []ManagementResponseListener         `json:"listeners"`
	NebulaCIDR                string                               `json:"nebulacidr"`
	OSAutoupdatePolicy        ManagementResponseOSAutoupdatePolicy `json:"osautoupdatepolicy"`
}

type ManagementResponseOSAutoupdatePolicy struct {
	Enabled                   bool `json:"enabled"`
	SecurityAutoupdateEnabled bool `json:"securityautoupdateenabled"`
	AllAutoupdateEnabled      bool `json:"allautoupdateenabled"`
	RestartAfterUpdate        bool `json:"restartafterupdate"`
	// 0 means any hour in day
	UpdateHour int `json:"updatehour"`
}

type ManagementResponseListener struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	ForwardPort int    `json:"forwardport"`
	ForwardHost string `json:"forwardhost"`
}

type ManagementResponseDNS struct {
	DnsRecords []string `json:"dnsrecords"`
	DnsHash    string   `json:"dnshash"`
}

type ManagementResponse struct {
	Status     string                    `json:"status"`
	ConfigData *ManagementResponseConfig `json:"config_data"`
	Dns        *ManagementResponseDNS    `json:"dns"`
}

type ManagementUPNResponse struct {
	Status     string                      `json:"status"`
	Hash       string                      `json:"hash"`
	ConfigData *[]ManagementResponseConfig `json:"config_data"`
	Dns        *ManagementResponseDNS      `json:"dns"`
}

type ManagementSimpleUPNResponseAccess struct {
	AccessID int    `json:"accessid"`
	Name     string `json:"name"`
	Secret   string `json:"secret"`
}

type ManagementSimpleUPNResponse struct {
	Status   string                               `json:"status"`
	Hash     string                               `json:"hash"`
	Accesses *[]ManagementSimpleUPNResponseAccess `json:"accesses"`
}

type ConfigDBResult struct {
	Id  int
	Ip  string
	Acc time.Time
	Fwc time.Time
	Crl time.Time
}

type UPNSimpleConfigDBResult struct {
	Id     int
	Acc    time.Time
	Name   string
	Secret string
}

type ConfigLighthouseDBResult struct {
	Crl time.Time
	Lgh string
}

func managementCheckDNSHash() string {
	db := model.Connection()
	var result time.Time
	db.Raw("select changed from key_value_stores kvs where id='DNS'").Scan(&result)
	hi := fmt.Sprintf("%s", result)
	log.Debug("DNS DB hash data: ", hi)
	hashstr := base64.URLEncoding.EncodeToString([]byte(hi))
	log.Debug("DNS DB hash: ", hashstr)
	return hashstr
}

func managementConfigUPNPost(w http.ResponseWriter, r *http.Request) {
	reqBody, _ := ioutil.ReadAll(r.Body)
	var dest ManagementRequest
	jerr := json.Unmarshal(reqBody, &dest)
	if jerr != nil {
		log.Error("JSON error: ", jerr)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	log.Debug("Management request: ", dest)
	log.Debug("Management request UPN: ", oauthRequestPayload(r).UPN)
	log.Debug("Management request accessId: ", oauthRequestPayload(r).AccessID)

	db := model.Connection()
	var result []UPNSimpleConfigDBResult

	db.Raw("select a.id, a.changed as acc, a.name, a.secret from entities e inner join user_accesses a on a.entity_id =e.id where e.upn = ? and valid_to > now() order by a.id",
		oauthRequestPayload(r).UPN).Scan(&result)
	hi := fmt.Sprintf("%v", result)
	// decrypt secrets
	for i, v := range result {
		var err error
		result[i].Secret, err = _cfg.ModelEncyptor.Decrypt(v.Secret)
		if err != nil {
			log.Error("Unable to decrypt secret: ", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
	}
	log.Debug("DB hash data: ", hi)
	hash := sha256.Sum256([]byte(hi))
	hashstr := base64.URLEncoding.EncodeToString(hash[:])
	log.Debug("DB hash: ", hashstr)

	if len(result) <= 0 {
		log.Debug("no access found for upn:", oauthRequestPayload(r).UPN)
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if dest.LogData != "" {
		log.Info(fmt.Sprintf("CLIENTAPP LOG: %s/%d: %s", oauthRequestPayload(r).UPN, dest.AccessID, dest.LogData))
		go logstore.LogItemStore(oauthRequestPayload(r).UPN, dest.AccessID, dest.LogData)
	}

	var cfg []ManagementSimpleUPNResponseAccess
	for _, a := range result {
		cfg = append(cfg, ManagementSimpleUPNResponseAccess{
			AccessID: a.Id,
			Name:     a.Name,
			Secret:   a.Secret,
		})
	}

	resp := ManagementSimpleUPNResponse{Status: "OK", Hash: hashstr, Accesses: &cfg}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		log.Error("json error: ", err)
	}
}

func managementStoreStatistic(upn string, ip string, access_id int, connected bool, over_restrictive_net bool, is_user bool) {
	db := model.Connection()

	if _cfg.Server.StoreHeartBeats {
		log_data := ManagementConnectionStatistics{
			UPN:                     upn,
			VpnIP:                   ip,
			Level:                   "info",
			Time:                    time.Now().UTC(),
			IsConnected:             connected,
			IsOverRestrictedNetwork: over_restrictive_net,
		}

		// store telemetry log
		var log_b []byte
		var err error
		if log_b, err = json.Marshal(&log_data); err != nil {
			log.Error("json error: ", err)
			return
		}
		logstore.LogItemStore(upn, access_id, string(log_b))
	}

	// save access statistics
	s := model.AccessStatistic{
		AccessID:                 access_id,
		IsConnected:              &connected,
		NebulaRestrictiveNetwork: &over_restrictive_net,
		Contacted:                time.Now().UTC(),
	}
	if result := db.Save(&s); result.Error != nil {
		log.Error("Unable to connect to database: ", result.Error)
	}

	// save access statistics by hours
	shour := s.Contacted.Format("2006010215")
	sid := fmt.Sprintf("%s|%s|%d", shour, upn, access_id)
	scontacted := true
	sconnected := connected
	hs := model.AccessStatisticData{
		ID:          sid,
		HourPeriod:  shour,
		UPN:         strings.ToLower(upn),
		AccessID:    access_id,
		IsContacted: &scontacted,
		IsConnected: &sconnected,
		IsUser:      &is_user,
	}
	if !connected {
		db = db.Omit("data_in", "data_out", "is_connected")
	} else {
		db = db.Omit("data_in", "data_out")
	}
	if result := db.Save(&hs); result.Error != nil {
		log.Error("Unable to connect to database: ", result.Error)
	}
}

func managementAutoupdate(w http.ResponseWriter, r *http.Request) {
	reqBody, _ := ioutil.ReadAll(r.Body)
	var dest ManagementOSAutoupdateRequest
	jerr := json.Unmarshal(reqBody, &dest)
	if jerr != nil {
		log.Error("JSON error: ", jerr)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	log.Debug("Management request: ", dest)
	log.Debug("Management request UPN: ", oauthRequestPayload(r).UPN)
	log.Debug("Management request accessId: ", oauthRequestPayload(r).AccessID)
	log.Debug("Management request clientId: ", oauthRequestPayload(r).ClientID)

	// only servers allowed
	if oauthRequestPayload(r).ClientID != "" {
		log.Debug("Not for users ..")
		http.Error(w, "Not allowed", http.StatusForbidden)
		return
	}

	// convert and serialize data
	data := ""
	autoupd := model.OSAutoUpdateType{
		Type:                 dest.Type,
		Name:                 dest.Name,
		Version:              dest.Version,
		Description:          dest.Description,
		LastUpdate:           dest.LastUpdate,
		LastUpdateOutput:     dest.LastUpdateOutput,
		Success:              dest.Success,
		SecurityUpdatesCount: dest.SecurityUpdatesCount,
		OtherUpdatesCount:    dest.OtherUpdatesCount,
		SecurityUpdates:      dest.SecurityUpdates,
		OtherUpdates:         dest.OtherUpdates,
	}
	if jsondata, err := json.Marshal(&autoupd); err == nil {
		data = string(jsondata)
	}

	// update auto-update results
	db := model.Connection()
	a := model.AccessDevice{AccessID: oauthRequestPayload(r).AccessID}
	if err := db.Model(&a).UpdateColumn("os_auto_update", data).Error; err != nil {
		log.Error("db error: ", err)
		http.Error(w, "server error", http.StatusInternalServerError)
	}
	return
}

func managementMessagePost(w http.ResponseWriter, r *http.Request) {
	reqBody, _ := ioutil.ReadAll(r.Body)
	var dest ManagementRequest
	jerr := json.Unmarshal(reqBody, &dest)
	if jerr != nil {
		log.Error("JSON error: ", jerr)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	log.Debug("Management request: ", dest)
	log.Debug("Management request UPN: ", oauthRequestPayload(r).UPN)
	log.Debug("Management request accessId: ", oauthRequestPayload(r).AccessID)
	log.Debug("Management request clientId: ", oauthRequestPayload(r).ClientID)

	db := model.Connection()

	isUser := false
	acid := oauthRequestPayload(r).AccessID
	// if connection comes from desktop app than we must translate accessId
	if oauthRequestPayload(r).ClientID != "" {
		acid = 0
		acid, _ = model.DacAccessConvertUserAccessIdToAccessId(oauthRequestPayload(r).AccessID, oauthRequestPayload(r).ClientID)
		log.Debug("Management request converted accessId: ", acid)
		isUser = true
	}

	var result ConfigDBResult

	db.Raw("select a.id, a.ip_address as ip, a.changed as acc, f.changed as fwc, (select changed from key_value_stores kvs where id='CRL') as crl from accesses a inner join fwconfigs f on f.id = a.fwconfig_id where a.id = ?",
		acid).Scan(&result)
	hi := fmt.Sprintf("%v", result)
	log.Debug("DB hash data: ", hi)
	hash := sha256.Sum256([]byte(hi))
	hashstr := base64.URLEncoding.EncodeToString(hash[:])
	log.Debug("DB hash: ", hashstr)

	if result.Id == 0 { // no access found
		log.Debug("no access found for upn:", oauthRequestPayload(r).UPN)
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// store logs
	if dest.LogData != "" {
		log.Info(fmt.Sprintf("NEBULA STDOUT: %s/%d: %s", oauthRequestPayload(r).UPN, acid, dest.LogData))
		go logstore.LogItemStore(oauthRequestPayload(r).UPN, acid, dest.LogData)
	}

	// store connection statistics
	go managementStoreStatistic(oauthRequestPayload(r).UPN, result.Ip, acid, dest.IsConnected, dest.OverWebSocket, isUser)

	var cfg *ManagementResponseConfig

	if hashstr != dest.ConfigHash {
		var a model.Access

		if result := db.
			Preload("Fwconfig.Fwconfigouts").
			Preload("Fwconfig.Fwconfigouts.FwconfigGroups").
			Preload("Fwconfig.Fwconfigouts.FwconfigGroups.Group").
			Preload("Fwconfig.Fwconfigins").
			Preload("Fwconfig.Fwconfigins.FwconfigGroups").
			Preload("Fwconfig.Fwconfigins.FwconfigGroups.Group").
			Preload("AccessListeners").
			Preload("AccessGroups").
			Preload("AccessGroups.Group").
			Preload("Certificate").
			First(&a, "id = ?", acid); result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			} else {
				log.Error("DB error: ", result.Error)
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}
		}

		var cs string
		var err error
		// normal config
		if cs, err = model.DownloadCreateNebulaConfig(db, &a, false, 0); err != nil {
			log.Error("YAML Marshal error: ", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		var listeners []ManagementResponseListener
		for _, list := range a.AccessListeners {
			listeners = append(listeners,
				ManagementResponseListener{
					Port:        list.ListenPort,
					Protocol:    list.Protocol,
					ForwardPort: list.ForwardPort,
					ForwardHost: list.ForwardHost,
				})
		}

		// desrialize auto update policy
		var updPolicy ManagementResponseOSAutoupdatePolicy
		var updPolicyModel model.OSAutoupdateConfigType
		if a.OSAutoupdateConfig != "" {
			// deserialize policy from json
			if json.Unmarshal([]byte(a.OSAutoupdateConfig), &updPolicyModel) == nil {
				updPolicy.Enabled = updPolicyModel.Enabled
				updPolicy.AllAutoupdateEnabled = updPolicyModel.AllAutoupdateEnabled
				updPolicy.SecurityAutoupdateEnabled = updPolicyModel.SecurityAutoupdateEnabled
				updPolicy.RestartAfterUpdate = updPolicyModel.RestartAfterUpdate
				updPolicy.UpdateHour = updPolicyModel.UpdateHour
			}
		}

		cfg = &ManagementResponseConfig{
			AccessID: a.ID,
			Name:     a.Name,
			UPN:      oauthRequestPayload(r).UPN,
			ConfigData: ManagementResponseConfigData{
				Hash:      hashstr,
				Data:      cs,
				IPAddress: a.IpAddress,
			},
			NebulaPunchBack:           *a.NebulaPunchBack,
			NebulaRestrictiveNetwork:  *a.NebulaRestrictiveNetwork,
			Autoupdate:                *a.Autoupdate,
			WebSocketUrl:              _cfg.Server.WebSocketUrl,
			WebSocketIPs:              _cfg.Server.WebSocketIPs,
			WebSocketUsernamePassword: basicauthGenerateRandomUsernamePassword(&a),
			ApplianceListeners:        listeners,
			NebulaCIDR:                model.SystemConfig().GetCIDR(),
			OSAutoupdatePolicy:        updPolicy,
		}
	}

	resp := ManagementResponse{Status: "OK", ConfigData: cfg}
	getDNS := managementCheckDNSHash()
	if getDNS != dest.DnsHash {
		dr, err := model.DownloadDNS(db)
		if err != nil {
			log.Error("DB DNS error: ", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
		dnsr := ManagementResponseDNS{DnsRecords: dr, DnsHash: getDNS}
		resp.Dns = &dnsr
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		log.Error("json error: ", err)
	}
}

func managementMessageLighthousePost(w http.ResponseWriter, r *http.Request) {
	reqBody, _ := ioutil.ReadAll(r.Body)
	var dest ManagementRequest
	jerr := json.Unmarshal(reqBody, &dest)
	if jerr != nil {
		log.Error("JSON error: ", jerr)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	log.Debug("Management request: ", dest)
	log.Debug("Management request UPN: ", oauthRequestPayload(r).UPN)
	log.Debug("Management request accessId: ", oauthRequestPayload(r).AccessID)

	db := model.Connection()
	var result ConfigLighthouseDBResult

	// find lighthouse
	lgh := ""
	var a model.LighthouseConfig
	for _, v := range model.SystemConfig().Lighthouses {
		if v.PublicIP == oauthRequestPayload(r).UPN {
			lgh = v.Hash
			a = v
		}
	}
	if lgh == "" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	db.Raw("select changed as crl, '' as lgh from key_value_stores kvs where id='CRL'").Scan(&result)
	result.Lgh = lgh
	hi := fmt.Sprintf("%s", result)
	log.Debug("DB hash data: ", hi)
	hash := sha256.Sum256([]byte(hi))
	hashstr := base64.URLEncoding.EncodeToString(hash[:])
	log.Debug("DB hash: ", hashstr)

	if dest.LogData != "" {
		log.Info(fmt.Sprintf("NEBULA STDOUT: lighthouse/%s: %s", oauthRequestPayload(r).UPN, dest.LogData))
		go logstore.LogItemStore("lighthouse/"+oauthRequestPayload(r).UPN, 0, dest.LogData)
	}

	var cfg *ManagementResponseConfig

	if hashstr != dest.ConfigHash {
		var cs string
		var err error
		if cs, err = model.DownloadCreateNebulaConfig(db, &a.Access, true, a.Port); err != nil {
			log.Error("YAML Marshal error: ", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		cfg = &ManagementResponseConfig{
			AccessID: 0,
			Name:     a.PublicIP,
			UPN:      a.PublicIP,
			ConfigData: ManagementResponseConfigData{
				Hash:      hashstr,
				Data:      cs,
				IPAddress: a.Access.IpAddress,
			},
			NebulaCIDR: model.SystemConfig().GetCIDR(),
		}
	}

	resp := ManagementResponse{Status: "OK", ConfigData: cfg}
	getDNS := managementCheckDNSHash()
	if getDNS != dest.DnsHash {
		dr, err := model.DownloadDNS(db)
		if err != nil {
			log.Error("DB DNS error: ", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
		dnsr := ManagementResponseDNS{DnsRecords: dr, DnsHash: getDNS}
		resp.Dns = &dnsr
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		log.Error("json error: ", err)
	}
}
