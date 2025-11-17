// Package traefik_gssapi a GSSAPI plugin for Traefik
package traefik_gssapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// Config the plugin configuration.
type Config struct {
	Keytab string `json:"keytab,omitempty" description:"Path to the keytab file."`
	Config string `json:"config,omitempty" description:"Path to the krb5.conf file."`
	Realm  string `json:"realm,omitempty" description:"Kerberos realm."`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Keytab: "/etc/krb5.keytab",
		Config: "/etc/krb5.conf",
		Realm:  "",
	}
}

// GssAuth a GssAuth plugin.
type GssAuth struct {
	next   http.Handler
	keytab *keytab.Keytab
	config *config.Config
	name   string
	realm  string
}

// New created a new GssAuth plugin.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	kt, err := keytab.Load(cfg.Keytab)
	if err != nil {
		return nil, err
	}
	conf, err := config.Load(cfg.Config)
	if err != nil {
		return nil, err
	}

	return &GssAuth{
		keytab: kt,
		next:   next,
		name:   name,
		config: conf,
		realm:  cfg.Realm,
	}, nil
}

func (a *GssAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if strings.HasPrefix(req.Header.Get("WWW-Authenticate"), "Basic ") {
		basic := strings.TrimPrefix(req.Header.Get("WWW-Authenticate"), "Basic ")
		authenticator := service.NewKRB5BasicAuthenticator(basic, a.config, nil, nil)

		_, b, err := authenticator.Authenticate()
		if err != nil {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		if b {
			a.next.ServeHTTP(rw, req)
			return
		}

	}

	gss := spnego.SPNEGOKRB5Authenticate(a.next, a.keytab)
	if rw.Header().Get("WWW-Authenticate") == "Negotiate" {
		if a.realm != "" {
			rw.Header().Add("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", a.realm))
		} else {
			rw.Header().Add("WWW-Authenticate", "Basic")
		}
	}
	gss.ServeHTTP(rw, req)
}
