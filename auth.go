// Package traefik_gssapi a GSSAPI plugin for Traefik
package traefik_gssapi

import (
	"context"
	"net/http"
	"text/template"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// Config the plugin configuration.
type Config struct {
	Keytab string `json:"keytab"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Keytab: "/etc/krb5.keytab",
	}
}

// GssAuth a GssAuth plugin.
type GssAuth struct {
	next     http.Handler
	keytab   *keytab.Keytab
	name     string
	template *template.Template
}

// New created a new GssAuth plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	kt, err := keytab.Load(config.Keytab)
	if err != nil {
		return nil, err
	}

	return &GssAuth{
		keytab:   kt,
		next:     next,
		name:     name,
		template: template.New("demo").Delims("[[", "]]"),
	}, nil
}

func (a *GssAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	spnego.SPNEGOKRB5Authenticate(a.next, a.keytab).ServeHTTP(rw, req)
}
