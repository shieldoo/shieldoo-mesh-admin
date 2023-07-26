package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/shieldoo/shieldoo-mesh-admin/logstore"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type DeviceLoginData struct {
	UPN      string
	Provider string
	Secret   string
	URI      string
}

func deviceloginCreate(code string, upn string, provider string, secret string, uri string) (err error) {
	ret := DeviceLoginData{
		UPN:      upn,
		Provider: provider,
		Secret:   secret,
		URI:      uri,
	}
	d, _ := json.Marshal(ret)
	db := model.Connection()
	dl := model.DeviceLogin{
		Id:         code,
		UPN:        upn,
		AccessData: string(d),
		Created:    time.Now().UTC(),
	}
	if result := db.Create(&dl); result.Error != nil {
		err = result.Error
		return
	}
	return
}

func deviceloginClaimUserName(jwttoken *jwt.Token) string {
	if val, ok := jwttoken.Claims.(jwt.MapClaims)["upn"]; ok {
		return val.(string)
	}
	if val, ok := jwttoken.Claims.(jwt.MapClaims)["unique_name"]; ok {
		return val.(string)
	}
	return jwttoken.Claims.(jwt.MapClaims)["preferred_username"].(string)
}

func deviceloginProcess(upn string, code string, uri string, provider string) (err error) {
	// get secret
	db := model.Connection()
	var cuser model.Entity
	if result := db.First(&cuser, "upn = ?", upn); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			log.Debug("db error: ", result.Error)
			err = errors.New("user not found")
			return
		} else {
			log.Error("DB error: ", result.Error)
			err = result.Error
			return
		}
	}
	deviceLoginExists, err := deviceloginExist(upn, code)
	if err != nil {
		return err
	}
	// create token for user
	if !deviceLoginExists {
		err = deviceloginCreate(code, upn, provider, cuser.Secret, uri)
		if err != nil {
			return err
		}
	}
	return
}

func deviceloginExist(upn string, code string) (bool, error) {
	// get secret
	db := model.Connection()
	var deviceLogin model.DeviceLogin

	if result := db.Where(&model.DeviceLogin{Id: code, UPN: upn}).First(&deviceLogin); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			log.Debug("db error: ", result.Error)
			return false, nil
		} else {
			log.Error("DB error: ", result.Error)
			return false, result.Error
		}
	}
	if deviceLogin != (model.DeviceLogin{}) {
		return true, nil
	} else {
		return false, nil
	}
}

func deviceloginGet(w http.ResponseWriter, r *http.Request) {

	db := model.Connection()
	vars := mux.Vars(r)
	e := model.DeviceLogin{}

	if result := db.First(&e, "id = ?", vars["id"]); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		} else {
			log.Error("DB error: ", result.Error)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, err := fmt.Fprintf(w, e.AccessData)
	if err != nil {
		return
	}
	// security log
	lgx := logstore.SecurityLogEntry{
		LogType:   logstore.LOGTYPE_USERDEVICELOGIN,
		UPN:       e.UPN,
		Timestamp: time.Now().UTC(),
		Message:   "User Device login success, access token returned.",
	}
	go lgx.Store()
	// delete token
	if result := db.Delete(model.DeviceLogin{}, "id = ?", e.Id); result.Error != nil {
		log.Error("DB error: ", result.Error)
	}
}
