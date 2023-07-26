package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/shieldoo/shieldoo-mesh-admin/cliapi"
	"github.com/shieldoo/shieldoo-mesh-admin/graph"
	"github.com/shieldoo/shieldoo-mesh-admin/graph/generated"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
	"github.com/shieldoo/shieldoo-mesh-admin/myjwt"
	utils "github.com/shieldoo/shieldoo-mesh-admin/utils"
	log "github.com/sirupsen/logrus"
)

var _cfg *utils.Config

type PublicWebConfig struct {
	AadEnebled  bool   `json:"aad_enabled"`
	AadTenantId string `json:"aad_tenant_id"`
}

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "OK!")
	log.Debug("Endpoint Hit: /api/health")
}

func configPage(w http.ResponseWriter, r *http.Request) {
	log.Debug("Endpoint Hit: /api/config")
	pubConfig := PublicWebConfig{
		AadEnebled:  model.SystemConfig().AADSyncConfig.Enabled,
		AadTenantId: model.SystemConfig().AADSyncConfig.AADTenantID,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(pubConfig)
}

func loginStart(w http.ResponseWriter, r *http.Request) {
	//if there is login from desktop agent ..
	code := r.URL.Query().Get("code")
	state := ""
	if len(code) >= 32 {
		state = "CODE:" + code
	} else {
		state = "NONE"
	}
	loginUrl := ""
	loginUrl = _cfg.Auth.AuthorizeUrl +
		"/" + "?state=" + url.QueryEscape(state) +
		"&audience=" + url.QueryEscape(_cfg.Auth.Shieldoo.TenantId)

	log.Debug("Endpoint Hit (GET): /login")
	http.Redirect(w, r, loginUrl, http.StatusFound)
}

func Run(cfg *utils.Config) {
	_cfg = cfg
	log.Info("Starting server at port: " + cfg.Server.Port)

	jwtMiddleware := jwtmiddleware.New(configureJwtValidator().ValidateToken)
	internalJwtMiddleware := jwtmiddleware.New(configureInternalJwtValidator().ValidateToken)

	myRouter := mux.NewRouter()

	oauthRouter := myRouter.PathPrefix("/api/oauth").Subrouter()
	oauthRouter.HandleFunc("/authorize", oauthPost).Methods("POST")
	oauthRouter.HandleFunc("/authorizeupn", oauthUPNPost).Methods("POST")
	oauthRouter.HandleFunc("/authorizelighthouse", oauthLighthousePost).Methods("POST")

	managementRouter := myRouter.PathPrefix("/api/management").Subrouter()
	managementRouter.HandleFunc("/message", managementMessagePost).Methods("POST")
	managementRouter.HandleFunc("/autoupdate", managementAutoupdate).Methods("POST")
	managementRouter.HandleFunc("/configupn", managementConfigUPNPost).Methods("POST")
	managementRouter.HandleFunc("/messagelighthouse", managementMessageLighthousePost).Methods("POST")
	managementRouter.Use(oauthMiddleware)

	myRouter.HandleFunc("/logindevice/{id}", deviceloginGet).Methods("GET")
	myRouter.HandleFunc("/login", loginStart).Methods("GET")
	myRouter.HandleFunc("/api/health", homePage)
	myRouter.HandleFunc("/api/config", configPage)
	myRouter.HandleFunc("/api/basicauth", basicauthCheck)

	sysApiRouter := myRouter.PathPrefix("/sysapi").Subrouter()
	sysApiRouter.HandleFunc("/user/{id}/device/{code}", sysapiUserDeviceLogin).Methods("POST")
	sysApiRouter.HandleFunc("/user/{id}/{origin}", sysapiUserDetails).Methods("GET")
	sysApiRouter.Use(internalJwtMiddleware.CheckJWT)
	sysApiRouter.Use(myjwt.JwtRoleCheckerSYSTEM)

	sysCliApiRouter := myRouter.PathPrefix("/cliapi").Subrouter()
	cliapi.Init(_cfg, sysCliApiRouter)

	graphsrv := handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{Resolvers: &graph.Resolver{}}))
	graphAdminRouter := myRouter.PathPrefix("/api/graph").Subrouter()
	graphAdminRouter.Handle("", graphsrv)
	graphAdminRouter.Use(jwtMiddleware.CheckJWT)

	var h http.Handler

	if _cfg.Server.Loglevel >= 5 {
		c := cors.New(cors.Options{
			AllowedOrigins:   []string{"*"},
			AllowCredentials: true,
			AllowedHeaders:   []string{"X-Requested-With", "Accept", "Content-Type", "Content-Length", "Accept-Encoding", "Accept-Language", "X-CSRF-Token", "Authorization"},
			AllowedMethods:   []string{"GET", "POST", "HEAD", "OPTIONS"},
		})

		h = c.Handler(myRouter)
	} else {
		h = myRouter
	}

	log.Fatal(http.ListenAndServe(":"+cfg.Server.Port, h))
}

func configureJwtValidator() *validator.Validator {
	issuerURL, err := url.Parse(_cfg.Auth.Issuer)
	if err != nil {
		log.Fatalf("failed to parse the issuer url: %v", err)
		os.Exit(1)
	}
	provider := jwks.NewCachingProvider(issuerURL, 5*time.Minute)
	jwtValidator, err := validator.New(
		provider.KeyFunc,
		validator.RS256,
		issuerURL.String(),
		_cfg.Auth.Audience, // audiences,
		validator.WithCustomClaims(
			func() validator.CustomClaims {
				return &myjwt.CustomClaimsShieldoo{}
			},
		),
		validator.WithAllowedClockSkew(30*time.Second),
	)

	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
		os.Exit(1)
	}
	return jwtValidator
}

func configureInternalJwtValidator() *validator.Validator {
	issuerURL, err := url.Parse(_cfg.Auth.InternalIssuer)
	if err != nil {
		log.Fatalf("failed to parse the issuer url: %v", err)
		os.Exit(1)
	}
	provider := jwks.NewCachingProvider(issuerURL, 5*time.Minute)
	jwtValidator, err := validator.New(
		provider.KeyFunc,
		validator.RS256,
		issuerURL.String(),
		[]string{}, // audiences,
		validator.WithCustomClaims(
			func() validator.CustomClaims {
				return &myjwt.CustomClaimsShieldoo{}
			},
		),
		validator.WithAllowedClockSkew(30*time.Second),
	)

	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
		os.Exit(1)
	}
	return jwtValidator
}
