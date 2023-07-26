package app

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/shieldoo/shieldoo-mesh-admin/model"
	"github.com/shieldoo/shieldoo-mesh-admin/utils"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func basicauthCheck(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	log.Debug("Endpoint Hit: /api/basicauth")
	log.Debug("/api/basicauth username: ", username)
	log.Debug("/api/basicauth password: ", password)
	if ok && basicauthValidateRandomUsernamePassword(username, password) {
		fmt.Fprintf(w, "OK!")
		return
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func basicauthGetPwd(usr string, salt string) string {
	data := usr + salt
	bdata := []byte(data)
	hash := sha256.Sum256(bdata)
	return base64.URLEncoding.EncodeToString(hash[:])
}

func basicauthValidateRandomUsernamePassword(username string, password string) bool {
	db := model.Connection()
	id, err := strconv.ParseInt(strings.Split(username, "-")[0], 10, 64)
	if err != nil {
		return false
	}

	var a model.Access

	if result := db.First(&a, "id = ?", id); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return false
		} else {
			log.Error("DB error: ", result.Error)
			return false
		}
	}
	pwd := basicauthGetPwd(username, a.Secret)
	return pwd == password
}

func basicauthGenerateRandomUsernamePassword(a *model.Access) string {
	usrrnd := fmt.Sprintf("%d-%s", a.ID, utils.GenerateRandomString(24))
	pwd := basicauthGetPwd(usrrnd, a.Secret)
	return fmt.Sprintf("%s:%s", usrrnd, pwd)
}
