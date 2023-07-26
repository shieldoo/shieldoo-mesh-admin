package cliapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/shieldoo/shieldoo-mesh-admin/logstore"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
	"github.com/shieldoo/shieldoo-mesh-admin/utils"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

var _cfg *utils.Config

const cliapiLogupn = "cliapi"

var shieldooHostname string

const CONTENT_TYPE = "Content-Type"
const CONTENT_TYPE_JSON = "application/json"

func Init(cfg *utils.Config, router *mux.Router) {
	_cfg = cfg

	// servers
	router.HandleFunc("/servers", serversList).Methods("GET")
	router.HandleFunc("/servers", serverCreate).Methods("POST")
	router.HandleFunc("/servers/{id}", serverDetail).Methods("GET")
	router.HandleFunc("/servers/{id}", serverUpdate).Methods("PUT")
	router.HandleFunc("/servers/{id}", serverDelete).Methods("DELETE")

	// firewalls
	router.HandleFunc("/firewalls", firewallList).Methods("GET")
	router.HandleFunc("/firewalls", firewallCreate).Methods("POST")
	router.HandleFunc("/firewalls/{id}", firewallDetail).Methods("GET")
	router.HandleFunc("/firewalls/{id}", firewallUpdate).Methods("PUT")
	router.HandleFunc("/firewalls/{id}", firewallDelete).Methods("DELETE")

	// groups
	router.HandleFunc("/groups", groupsList).Methods("GET")
	router.HandleFunc("/groups/{id}", groupDetail).Methods("GET")

	// authentication
	router.Use(oauthAuthenticate)
}

type JWTData struct {
	jwt.StandardClaims
	ShieldooClaims map[string]string `json:"shieldoo"`
}

func validateJwtToken(tokenString string) (bool, JWTData) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTData{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(model.SystemConfig().CliApiConfig.ApiKey), nil
	})
	if err != nil {
		return false, JWTData{}
	}
	if claims, ok := token.Claims.(*JWTData); ok && token.Valid {
		// validate custom claims
		if claims.ShieldooClaims["instance"] != getShieldooHostname() {
			return false, JWTData{}
		}
		return true, *claims
	}
	return false, JWTData{}
}

func oauthAuthenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !model.SystemConfig().CliApiConfig.Enabled {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// validate JWT token from header AuthToken
		token := r.Header.Get("AuthToken")
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		valid, _ := validateJwtToken(token)
		if !valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getShieldooHostname() string {
	if shieldooHostname == "" {
		parsedURL, err := url.Parse(_cfg.Server.URI)
		if err == nil {
			shieldooHostname = parsedURL.Hostname()
		}
	}
	return shieldooHostname
}

func formatId(id int, resource string) string {
	return getShieldooHostname() + ":" + resource + ":" + strconv.Itoa(id)
}

func convertGroupToCliapi(group *model.Group) Group {
	ret := Group{
		Id:       formatId(group.ID, "groups"),
		Name:     group.Name,
		ObjectId: group.ObjectId,
	}
	return ret
}

func convertServerToCliapi(server *model.Entity, config bool) Server {
	ret := Server{
		Id:          formatId(server.ID, "servers"),
		Name:        server.Name,
		Description: server.Description,
	}
	if len(server.Accesses) > 0 {
		acc := server.Accesses[0]
		for _, g := range acc.AccessGroups {
			ret.Groups = append(ret.Groups, convertGroupToCliapi(&g.Group))
		}
		ret.Firewall = convertFirewallToCliapi(&acc.Fwconfig)
		for _, l := range acc.AccessListeners {
			ret.Listeners = append(ret.Listeners, Listener{
				ListenPort:  l.ListenPort,
				Protocol:    l.Protocol,
				ForwardPort: l.ForwardPort,
				ForwardHost: l.ForwardHost,
				Description: l.Description,
			})
		}
		if acc.Autoupdate != nil {
			ret.Autoupdate = *acc.Autoupdate
		}
		ret.IpAddress = acc.IpAddress
		ret.Firewall = convertFirewallToCliapi(&acc.Fwconfig)
		if config {
			ret.Configuration = generateConfigFromAccess(&acc)
		}
		// os update policy
		if acc.OSAutoupdateConfig != "" {
			var updPolicy model.OSAutoupdateConfigType
			if json.Unmarshal([]byte(acc.OSAutoupdateConfig), &updPolicy) == nil {
				ret.OSUpdatePolicy.AllAutoupdateEnabled = updPolicy.AllAutoupdateEnabled
				ret.OSUpdatePolicy.Enabled = updPolicy.Enabled
				ret.OSUpdatePolicy.RestartAfterUpdate = updPolicy.RestartAfterUpdate
				ret.OSUpdatePolicy.SecurityAutoupdateEnabled = updPolicy.SecurityAutoupdateEnabled
				ret.OSUpdatePolicy.UpdateHour = updPolicy.UpdateHour
			}
		}
	}
	return ret
}

func convertFirewallToCliapi(fw *model.Fwconfig) Firewall {
	ret := Firewall{
		Id:   formatId(fw.ID, "firewalls"),
		Name: fw.Name,
	}
	for _, g := range fw.Fwconfigins {
		r := FirewallRule{
			Protocol: g.Proto,
			Port:     g.Port,
			Host:     g.Host,
		}
		for _, gr := range g.FwconfigGroups {
			r.Groups = append(r.Groups, convertGroupToCliapi(&gr.Group))
		}
		ret.RulesIn = append(ret.RulesIn, r)
	}
	for _, g := range fw.Fwconfigouts {
		r := FirewallRule{
			Protocol: g.Proto,
			Port:     g.Port,
			Host:     g.Host,
		}
		for _, gr := range g.FwconfigGroups {
			r.Groups = append(r.Groups, convertGroupToCliapi(&gr.Group))
		}
		ret.RulesOut = append(ret.RulesOut, r)
	}
	return ret
}

func groupsList(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	groups, err := model.DacGroupGetAll(name)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var dest []Group
	for _, g := range groups {
		dest = append(dest, convertGroupToCliapi(&g))
	}
	w.Header().Set(CONTENT_TYPE, CONTENT_TYPE)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(dest)
}

func groupDetail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	strid := vars["id"]
	id := extractId(strid, "groups")
	group, err := model.DacGroupGet(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Group not found"))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(CONTENT_TYPE, CONTENT_TYPE)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(convertGroupToCliapi(&group))
}

func firewallList(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	firewalls, err := model.DacFwconfigGetAll(name)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var dest []Firewall
	for _, fw := range firewalls {
		dest = append(dest, convertFirewallToCliapi(&fw))
	}
	w.Header().Set(CONTENT_TYPE, CONTENT_TYPE)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(dest)
}

func firewallCreate(w http.ResponseWriter, r *http.Request) {
	log.Debug("firewallCreate ..")
	// create FW from data
	var fw Firewall
	err := json.NewDecoder(r.Body).Decode(&fw)
	if err != nil {
		log.Error("firewallCreate: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// translate objects to model objects
	fwmodel, err := translateFWToModel(&fw)
	if err != nil {
		log.Debug("firewallCreate validation error: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	// save to DB
	err = model.DacFwconfigSave(cliapiLogupn, &fwmodel)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	utils.BreakAADWaitLoop()
	// return created object
	ret, err := model.DacFwconfigGet(fwmodel.ID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	go model.LogStoreDatachange(logstore.LOGTYPE_DATAINSERT, cliapiLogupn, &ret, nil)
	w.Header().Set(CONTENT_TYPE, CONTENT_TYPE)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(convertFirewallToCliapi(&ret))
}

func firewallUpdate(w http.ResponseWriter, r *http.Request) {
	log.Debug("firewallUpdate ..")
	// update fw from data
	var fw Firewall
	vars := mux.Vars(r)
	strid := vars["id"]
	id := extractId(strid, "firewalls")
	err := json.NewDecoder(r.Body).Decode(&fw)
	if err != nil {
		log.Error("firewallUpdate: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// translate objects to model objects
	fwmodel, err := translateFWToModel(&fw)
	if err != nil {
		log.Debug("firewallUpdate validation error: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	fwmodel.ID = id
	// original object
	fworig, err := model.DacFwconfigGet(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Debug("firewallUpdate not found: ", err)
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Firewall not found"))
			return
		}
		log.Error("firewallUpdate: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// if are not equal, we don't have to update
	if isEqualFwconfigModel(&fworig, &fwmodel) {
		log.Debug("firewallUpdate: no changes")
		w.WriteHeader(http.StatusOK)
		w.Header().Set(CONTENT_TYPE, CONTENT_TYPE)
		json.NewEncoder(w).Encode(convertFirewallToCliapi(&fworig))
		return
	}
	// save to DB
	log.Debug("firewallUpdate: save to DB")
	err = model.DacFwconfigSave(cliapiLogupn, &fwmodel)
	if err != nil {
		log.Error("firewallUpdate: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	utils.BreakAADWaitLoop()
	// return created object
	ret, err := model.DacFwconfigGet(id)
	if err != nil {
		log.Error("firewallUpdate: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	go model.LogStoreDatachange(logstore.LOGTYPE_DATAUPDATE, cliapiLogupn, &ret, &fworig)
	w.Header().Set(CONTENT_TYPE, CONTENT_TYPE)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(convertFirewallToCliapi(&ret))
}

func firewallDetail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	strid := vars["id"]
	id := extractId(strid, "firewalls")
	firewall, err := model.DacFwconfigGet(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Firewall not found"))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(CONTENT_TYPE, CONTENT_TYPE)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(convertFirewallToCliapi(&firewall))
}

func firewallDelete(w http.ResponseWriter, r *http.Request) {
	log.Debug("firewallDelete ..")
	vars := mux.Vars(r)
	strid := vars["id"]
	id := extractId(strid, "firewalls")
	f, err := model.DacFwconfigGet(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Debug("firewallDelete not found: ", err)
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Firewall not found"))
			return
		}
		log.Error("firewallDelete: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = model.DacFwconfigDelete(id, cliapiLogupn)
	if err != nil {
		if err.Error() == "Object is associated to other records." || err.Error() == "Default firewall config can't be deleted" {
			log.Debug("firewallDelete: ", err)
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(err.Error()))
			return
		}
		log.Error("firewallDelete: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	utils.BreakAADWaitLoop()
	go model.LogStoreDatachange(logstore.LOGTYPE_DATADELETE, cliapiLogupn, &f, nil)
	w.WriteHeader(http.StatusOK)
}

func serversList(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	servers, err := model.DacServerGetAll(name)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var dest []Server
	for _, s := range servers {
		srv := convertServerToCliapi(&s, name != "")
		dest = append(dest, srv)
	}
	w.Header().Set(CONTENT_TYPE, CONTENT_TYPE)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(dest)
}

func serverCreate(w http.ResponseWriter, r *http.Request) {
	log.Debug("serverCreate ..")
	var s Server
	err := json.NewDecoder(r.Body).Decode(&s)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// translate model
	m, a, err := translateServerToModel(&s)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	// save to DB
	log.Debug("serverCreate: save to DB")
	err = model.DacEntityServerSave(cliapiLogupn, &m, &m, &a, &a)
	if err != nil {
		log.Error("serverCreate: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	// return created object
	ret, err := model.DacEntityAccesses(m.ID)
	if err != nil {
		log.Error("serverCreate: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	go model.LogStoreDatachange(logstore.LOGTYPE_DATAINSERT, cliapiLogupn, &ret, nil)
	w.Header().Set(CONTENT_TYPE, CONTENT_TYPE)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(convertServerToCliapi(&ret, true))
}

func serverDetail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	strid := vars["id"]
	id := extractId(strid, "servers")
	server, err := model.DacEntityAccesses(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Server not found"))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(CONTENT_TYPE, CONTENT_TYPE)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(convertServerToCliapi(&server, true))
}

func serverUpdate(w http.ResponseWriter, r *http.Request) {
	log.Debug("serverUpdate ..")
	vars := mux.Vars(r)
	strid := vars["id"]
	id := extractId(strid, "servers")
	var s Server
	err := json.NewDecoder(r.Body).Decode(&s)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// check if server exists
	orig, err := model.DacEntityAccesses(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Server not found"))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// translate model
	change, m, a, err := translateServerToOriginalModel(&orig, &s)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	// if there is no change, return
	if !change {
		log.Debug("serverUpdate: no change")
		w.Header().Set(CONTENT_TYPE, CONTENT_TYPE)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(convertServerToCliapi(&orig, true))
		return
	}
	// save to DB
	log.Debug("serverUpdate: save to DB")
	var origacc model.Access
	if len(orig.Accesses) > 0 {
		origacc = orig.Accesses[0]
	}
	err = model.DacEntityServerSave(cliapiLogupn, &m, &orig, &a, &origacc)
	if err != nil {
		log.Error("serverUpdate: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	// return updated object
	ret, err := model.DacEntityAccesses(m.ID)
	if err != nil {
		log.Error("serverUpdate: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	go model.LogStoreDatachange(logstore.LOGTYPE_DATAUPDATE, cliapiLogupn, &ret, nil)
	w.Header().Set(CONTENT_TYPE, CONTENT_TYPE)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(convertServerToCliapi(&ret, true))
}

func serverDelete(w http.ResponseWriter, r *http.Request) {
	log.Debug("serverDelete ..")
	vars := mux.Vars(r)
	strid := vars["id"]
	id := extractId(strid, "servers")
	s, err := model.DacEntityGet(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Server not found"))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if s.EntityType != model.ENTITY_SERVER {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err = model.DacEntityDelete(id, cliapiLogupn)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	go model.LogStoreDatachange(logstore.LOGTYPE_DATADELETE, cliapiLogupn, &s, nil)
	w.WriteHeader(http.StatusOK)
}
