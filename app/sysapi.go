package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
	"github.com/shieldoo/shieldoo-mesh-admin/utils"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type SysApiUserDetail struct {
	UPN    string   `json:"upn"`
	Origin string   `json:"origin"`
	Name   string   `json:"name"`
	Roles  []string `json:"roles"`
}

func sysapiUserDetails(w http.ResponseWriter, r *http.Request) {
	db := model.Connection()
	vars := mux.Vars(r)
	e := model.Entity{}

	log.Debug("SYSAPI: id: ", vars["id"])
	log.Debug("SYSAPI: origin: ", vars["origin"])

	if result := db.First(&e, "upn = ?", strings.ToLower(vars["id"])); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		} else {
			log.Error("DB error: ", result.Error)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
	}

	// if AAD integration enabled then enforce tenant id
	if model.SystemConfig().AADSyncConfig.Enabled {
		log.Debug("SYSAPI: AAD tenant: ", model.SystemConfig().AADSyncConfig.AADTenantID)
		if e.Origin != vars["origin"] {
			log.Debug("SYSAPI: tenant id not match: ", e.Origin, " vs ", vars["origin"])
			http.Error(w, "Not found - tenant_id not match", http.StatusNotFound)
			return
		}
	}

	var roles []string
	var ret []string
	if json.Unmarshal([]byte(e.Roles), &roles) == nil {
		for _, i := range roles {
			if i != model.ROLE_USER {
				ret = append(ret, i)
			}
		}
	}
	ret = append(ret, model.ROLE_USER)
	dest := SysApiUserDetail{
		UPN:    e.UPN,
		Name:   e.Name,
		Origin: e.Origin,
		Roles:  ret,
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(dest); err != nil {
		log.Error("json error: ", err)
	}
	go utils.SegmentEventUserLogin(e.UPN)
}

func sysapiUserDeviceLogin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = "unknown"
	}
	log.Debug("SYSAPI: id: ", vars["id"])
	log.Debug("SYSAPI: code: ", vars["code"])
	log.Debug("SYSAPI: provider: ", provider)

	err := deviceloginProcess(vars["id"], strings.Replace(vars["code"], "CODE:", "", 1),
		_cfg.Server.URI, provider)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err != nil {
		log.Error("user device login error: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
		go utils.SegmentEventUserClientLogin(vars["id"])
	}

}
