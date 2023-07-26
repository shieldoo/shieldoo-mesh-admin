package myjwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/shieldoo/shieldoo-mesh-admin/utils"
	log "github.com/sirupsen/logrus"
)

var _cfg *utils.Config

func Init(cfg *utils.Config) {
	_cfg = cfg
}

const (
	ROLE_SYSTEM        = "SYSTEM"
	ROLE_ADMINISTRATOR = "ADMINISTRATOR"
	ROLE_USER          = "USER"
)

type CustomClaimsShieldoo struct {
	Name          string   `json:"name"`
	Upn           string   `json:"upn,omitempty"`
	UniqueName    string   `json:"unique_name,omitempty"`
	PreferredName string   `json:"preferred_username,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	Provider      string   `json:"provider,omitempty"`
	Tenant        string   `json:"tenant,omitempty"`
}

// Validate does nothing for this example.
func (c *CustomClaimsShieldoo) Validate(ctx context.Context) error {
	return nil
}

func ClaimIsInRole(ctx context.Context, role string) bool {
	claims := ctx.Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
	cc := claims.CustomClaims.(*CustomClaimsShieldoo)

	if cc.Roles != nil {
		for _, s := range cc.Roles {
			if role == s {
				return true
			}
		}
	}
	return false
}

func ClaimGetCustomFromContext(ctx context.Context) *CustomClaimsShieldoo {
	claims := ctx.Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
	return claims.CustomClaims.(*CustomClaimsShieldoo)
}

func ClaimGetCustom(r *http.Request) *CustomClaimsShieldoo {
	ctx := r.Context()
	return ClaimGetCustomFromContext(ctx)
}

func ClaimGetRolesFromContext(ctx context.Context) []string {
	claims := ctx.Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
	cc := claims.CustomClaims.(*CustomClaimsShieldoo)
	if cc.Roles == nil {
		return []string{}
	} else {
		return cc.Roles
	}
}

func ClaimGetRoles(r *http.Request) []string {
	ctx := r.Context()
	return ClaimGetRolesFromContext(ctx)
}

func ClaimUserName(r *http.Request) string {
	return ClaimUserNameFromContext(r.Context())
}

func ClaimUserNameFromContext(ctx context.Context) string {
	claims := ctx.Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
	cc := claims.CustomClaims.(*CustomClaimsShieldoo)

	upn := ""

	if cc.Upn != "" {
		upn = cc.Upn
	} else if cc.UniqueName != "" {
		upn = cc.UniqueName
	} else {
		upn = cc.PreferredName
	}
	return strings.ToLower(upn)
}

func ClaimFullName(r *http.Request) string {
	claims := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
	cc := claims.CustomClaims.(*CustomClaimsShieldoo)
	return cc.Name
}

func JwtRoleCheckerUSER(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ClaimIsInRole(r.Context(), ROLE_USER) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func JwtRoleCheckerADMINISTRATOR(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ClaimIsInRole(r.Context(), ROLE_ADMINISTRATOR) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func JwtRoleCheckerSYSTEM(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ClaimIsInRole(r.Context(), ROLE_SYSTEM) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func JwtRoleCheckerContextADMINISTRATOR(ctx context.Context) (err error) {
	log.Debug("checking ROLE_ADMINISTRATOR")
	if !ClaimIsInRole(ctx, ROLE_ADMINISTRATOR) {
		err = fmt.Errorf("Access forbidden, not in role " + ROLE_ADMINISTRATOR)
	}
	return
}

func JwtRoleCheckerContextUSER(ctx context.Context) (err error) {
	log.Debug("checking ROLE_USER")
	if !ClaimIsInRole(ctx, ROLE_USER) {
		err = fmt.Errorf("Access forbidden, not in role " + ROLE_USER)
	}
	return
}

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

var cert string = ""
var certkid string = ""
var certTimestamp time.Time = time.Now().UTC()

func JwtMSFTGetPemCert(token *jwt.Token) (string, error) {
	log.Debug("JWT validate: Get PEM Cert")
	if certkid != token.Header["kid"] || certTimestamp.Add(3600*time.Second).Before(time.Now().UTC()) {
		log.Info("JWT validate: Load PEM Cert")
		resp, err := http.Get("https://login.microsoftonline.com/common/discovery/v2.0/keys")

		if err != nil {
			return cert, err
		}
		defer resp.Body.Close()

		var jwks = Jwks{}
		err = json.NewDecoder(resp.Body).Decode(&jwks)

		if err != nil {
			return cert, err
		}

		for k, _ := range jwks.Keys {
			if token.Header["kid"] == jwks.Keys[k].Kid {
				cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
				certkid = jwks.Keys[k].Kid
				log.Debug("JWT validate: Load PEM Cert (cert): ", cert)
				log.Debug("JWT validate: Load PEM Cert: (kid): ", certkid)
			}
		}

		if cert == "" {
			err := errors.New("Unable to find appropriate key.")
			return cert, err
		}

		certTimestamp = time.Now().UTC()
	}

	return cert, nil
}
