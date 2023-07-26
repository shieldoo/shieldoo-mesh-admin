package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shieldoo/shieldoo-mesh-admin/authserver"
	"github.com/shieldoo/shieldoo-mesh-admin/logstore"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
	"github.com/shieldoo/shieldoo-mesh-admin/utils"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type OAuthLoginRequest struct {
	AccessID      int    `json:"access_id"`
	Timestamp     int64  `json:"timestamp"`
	Key           string `json:"key"`
	ClientID      string `json:"clientid"`
	ClientOS      string `json:"clientos"`
	ClientInfo    string `json:"clientinfo"`
	ClientVersion string `json:"clientversion"`
}

type OAuthUPNLoginRequest struct {
	Upn       string `json:"upn"`
	Timestamp int64  `json:"timestamp"`
	Key       string `json:"key"`
}

type OAuthLighthouseLoginRequest struct {
	PublicIp  string `json:"publicip"`
	Timestamp int64  `json:"timestamp"`
	Key       string `json:"key"`
}

type OAuthLoginResponse struct {
	JWTToken string    `json:"jwt"`
	ValidTo  time.Time `json:"valid_to"`
}

func oauthLighthousePost(w http.ResponseWriter, r *http.Request) {

	reqBody, _ := ioutil.ReadAll(r.Body)
	var dest OAuthLighthouseLoginRequest
	jerr := json.Unmarshal(reqBody, &dest)
	if jerr != nil {
		log.Error("JSON error: ", jerr)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	found := false
	for _, v := range model.SystemConfig().Lighthouses {
		if v.PublicIP == dest.PublicIp {
			found = true
		}
	}
	if !found {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := oauthValidateKey(dest.Timestamp, model.SystemConfig().Secret, dest.Key); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	oauthBase(w, r, dest.PublicIp, 0, "")
}

func oauthUPNPost(w http.ResponseWriter, r *http.Request) {
	// get acccess and check secret
	db := model.Connection()

	reqBody, _ := ioutil.ReadAll(r.Body)
	var dest OAuthUPNLoginRequest
	jerr := json.Unmarshal(reqBody, &dest)
	if jerr != nil {
		log.Error("JSON error: ", jerr)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	var e model.Entity

	if result := db.
		First(&e, "upn = ?", dest.Upn); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Debug("entity id not found")
			return
		} else {
			log.Error("DB error: ", result.Error)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
	}

	if err := oauthValidateKey(dest.Timestamp, e.Secret, dest.Key); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	oauthBase(w, r, e.UPN, 0, "")
}

func oauthPost(w http.ResponseWriter, r *http.Request) {
	// get acccess and check secret
	db := model.Connection()

	reqBody, _ := ioutil.ReadAll(r.Body)
	var dest OAuthLoginRequest
	jerr := json.Unmarshal(reqBody, &dest)
	if jerr != nil {
		log.Error("JSON error: ", jerr)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	var entityId int
	var secret string

	if dest.ClientID == "" {
		var a model.Access
		if result := db.
			First(&a, "id = ?", dest.AccessID); result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				log.Debug("access id not found")
				return
			} else {
				log.Error("DB error: ", result.Error)
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}
		}
		secret = a.Secret
		entityId = a.EntityID
	} else {
		var a model.UserAccess
		if result := db.
			First(&a, "id = ?", dest.AccessID); result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				log.Debug("access id not found")
				return
			} else {
				log.Error("DB error: ", result.Error)
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}
		}
		secret = a.Secret
		entityId = a.EntityID
	}

	if err := oauthValidateKey(dest.Timestamp, secret, dest.Key); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var e model.Entity
	if resultent := db.
		First(&e, "id = ?", entityId); resultent.Error != nil {
		if errors.Is(resultent.Error, gorm.ErrRecordNotFound) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Debug("entity id not found")
			return
		} else {
			log.Error("DB error: ", resultent.Error)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
	}

	if dest.ClientID != "" {
		// if there is client_id we have to check if Access exists, if not, we have to create new one
		model.DacAccessCheckOrCreateForUser(e.UPN, dest.AccessID, dest.ClientID, dest.ClientInfo, dest.ClientOS, dest.ClientVersion)
		go utils.SegmentEventUserVPNConnectionLogin(e.UPN)
	} else {
		// save statistics for servers
		model.DacAccessSaveDeviceStatisticsForDevice(e.UPN, dest.AccessID, dest.ClientInfo, dest.ClientOS, dest.ClientVersion)
		go utils.SegmentEventServerVPNConnectionLogin(e.UPN)
	}

	oauthBase(w, r, e.UPN, dest.AccessID, dest.ClientID)
}

func oauthBase(w http.ResponseWriter, r *http.Request, upn string, access_id int, client_id string) {
	jwt, validto, err := authserver.CreateToken(upn, access_id, client_id)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		log.Error("OAuth error: ", err)
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	resp := OAuthLoginResponse{JWTToken: jwt, ValidTo: validto}

	log.Debug("OAuth created JWT token: ", resp)

	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		log.Error("json error: ", err)
	}

	// security log
	lgx := logstore.SecurityLogEntry{
		LogType:   logstore.LOGTYPE_DEVICELOGIN,
		UPN:       upn,
		Timestamp: time.Now().UTC(),
		Message:   "Device login success, JWT token generated.",
	}
	go lgx.Store()
}

func oauthAuthHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("No Authorization header") // No error, just no token
	}

	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

func oauthValidateKey(timestamp int64, secret string, key string) error {
	//validate timestamp
	tnow := time.Now().UTC().Unix()
	if (timestamp-300) > tnow || (timestamp+300) < tnow {
		log.Debug("timestamp is not valid now/received: ", tnow, timestamp)
		return errors.New("timestamp is not valid")
	}

	//validate password
	keymaterial := strconv.FormatInt(timestamp, 10) + "|" + secret
	hash := sha256.Sum256([]byte(keymaterial))
	if base64.URLEncoding.EncodeToString(hash[:]) != key {
		log.Debug("key is not valid")
		log.Debug("key is not valid -> key: ", key)
		log.Debug("key is not valid -> keymaterial: ", keymaterial)
		log.Debug("key is not valid -> lockey: ", base64.URLEncoding.EncodeToString(hash[:]))
		return errors.New("key is not valid")
	}
	return nil
}

func oauthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		bearer, err := oauthAuthHeader(r)
		if err != nil {
			log.Debug("oauth middleware unauthorized: ", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		payload, err := authserver.VerifyToken(bearer)
		if err != nil {
			log.Debug("oauth middleware unauthorized: ", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// If we get here, everything worked and we can set the
		// user property in context.
		newRequest := r.WithContext(context.WithValue(r.Context(), "token", payload))
		// Update the current request with the new context information.
		*r = *newRequest

		next.ServeHTTP(w, r)
	})
}

func oauthRequestPayload(r *http.Request) *authserver.Payload {
	return r.Context().Value("token").(*authserver.Payload)
}
