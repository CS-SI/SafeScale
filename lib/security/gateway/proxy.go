package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	oidc "github.com/coreos/go-oidc"
	"github.com/gobwas/glob"
	"github.com/gorilla/websocket"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"

	"github.com/CS-SI/SafeScale/lib/security/model"
)

var ctx = context.Background()
var verifier *oidc.IDTokenVerifier
var cfg *proxyConfig
var config oauth2.Config
var state = uuid.Must(uuid.NewV4()).String()
var upgrader = websocket.Upgrader{} // use default options

type requestInfo struct {
	service  string
	resource string
	token    string
	method   string
}

func parseRequest(req *http.Request) requestInfo {
	tokens := strings.Split(req.URL.Path, "/")
	service := tokens[1]
	resource := strings.Join(tokens[2:], "/")

	// Get token from the Authorization header
	// format: Authorization: Bearer
	authTokens, ok := req.Header["Authorization"]
	token := ""
	if ok && len(tokens) >= 1 {
		token = strings.TrimPrefix(authTokens[0], "Bearer ")
	}
	return requestInfo{
		service:  service,
		resource: resource,
		token:    token,
		method:   req.Method,
	}
}

func authenticate(token string) (string, int) {

	// If the token is missing redirect to the login page
	if token == "" {

		return "", http.StatusTemporaryRedirect
	}

	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return "", http.StatusForbidden
	}
	// Extract custom claims
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil || !claims.Verified {
		// Token is invalid

		return "", http.StatusForbidden
	}
	return claims.Email, http.StatusOK
}

func authorize(email, service, resource, method string) bool {

	da := model.NewDataAccess(cfg.DatabaseDialect, cfg.DatabaseDSN)
	srv := da.GetServiceByName(service)
	if srv == nil {
		return false
	}

	permissions := da.GetUserAccessPermissionsByService(email, service)

	for _, permission := range permissions {
		pattern := permission.ResourcePattern
		g, err := glob.Compile(pattern)
		if err != nil {
			continue
		}
		if g.Match(resource) && (permission.Action == method) || (permission.Action == "ALL") {
			return true
		}
	}
	return false

}

func getServiceURL(service, resource string) (*url.URL, error) {
	da := model.NewDataAccess(cfg.DatabaseDialect, cfg.DatabaseDSN)
	srv := da.GetServiceByName(service)
	if srv == nil {
		return nil, fmt.Errorf("No route define to serve resource %s from service %s", service, resource)
	}
	surl := strings.Join([]string{srv.BaseURL, resource}, "/")
	return url.Parse(surl)
}

func httpForward(w http.ResponseWriter, req *http.Request, url *url.URL) {
	// create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(url)

	// Update the headers to allow for SSL redirection
	req.URL.Host = url.Host
	req.URL.Scheme = url.Scheme
	req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))

	req.Host = url.Host

	//add CORS to the respoonse header
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "X-Requested-With")

	// Note that ServeHttp is non blocking and uses a go routine under the hood
	proxy.ServeHTTP(w, req)

}

//httpProxyFunc forward authorized request to pr++++++++++++otected service
func httpProxyFunc(w http.ResponseWriter, r *http.Request) {

	info := parseRequest(r)

	if !authorizedAndAuthenticated(w, r, info, "WS") {
		return
	}

	proxyUrl, err := getServiceURL(info.service, info.resource)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}

	httpForward(w, r, proxyUrl)

}

func authorizedAndAuthenticated(w http.ResponseWriter, r *http.Request, info requestInfo, method string) bool {
	if cfg.AuthenticationEnabled() {
		email, status := authenticate(info.token)

		if status == http.StatusTemporaryRedirect {
			http.Redirect(w, r, config.AuthCodeURL(state), http.StatusFound)
			return false
		}
		if status != http.StatusOK {
			http.Error(w, http.StatusText(status), status)
			return false
		}

		ok := authorize(email, info.service, info.resource, info.method)
		if !ok {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return false
		}
	}

	return true
}

func fowardWSMessages(from *websocket.Conn, to *websocket.Conn) {
	defer func() {
		fromErr := from.Close()
		if fromErr != nil {
			log.Error(fromErr)
		}
	}()
	defer func() {
		toErr := to.Close()
		if toErr != nil {
			log.Error(toErr)
		}
	}()
	for {
		mType, buffer, err := from.ReadMessage()
		if err != nil {
			break
		}
		err = to.WriteMessage(mType, buffer)
		if err != nil {
			break
		}
	}
}

func wsProxyFunc(w http.ResponseWriter, r *http.Request) {
	info := parseRequest(r)
	if !authorizedAndAuthenticated(w, r, info, "WS") {
		return
	}

	cOrig, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	theUrl, err := getServiceURL(info.service, info.resource)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	header := http.Header{}
	cDest, _, err := websocket.DefaultDialer.Dial(theUrl.String(), header)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}

	go fowardWSMessages(cOrig, cDest)
	go fowardWSMessages(cDest, cOrig)
}

func proxify() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if websocket.IsWebSocketUpgrade(r) { //Web socker connexion
			wsProxyFunc(w, r)
		} else { //HTTP request
			httpProxyFunc(w, r)
		}

	})
}

type proxyConfig struct {
	OpenIDURL          string
	OpenIDClientID     string
	OpenIDClientSecret string
	OpenIDRedirectURL  string
	Certificate        string
	PrivateKey         string
	DatabaseDialect    string
	DatabaseDSN        string
}

func loadConfig() (cfg *proxyConfig, err error) {
	viper.SetConfigName("security")         // name of config file (without extension)
	viper.AddConfigPath("/etc/safescale/")  // path to look for the config file in
	viper.AddConfigPath("$HOME/.safescale") // call multiple times to add many search paths
	viper.AddConfigPath(".")                // optionally look for config in the working directory
	err = viper.ReadInConfig()             // Find and read the config file
	if err != nil {                         // Handle errors reading the config file
		return nil, fmt.Errorf("Fatal error reading config file: %s", err)
	}

	cfg = &proxyConfig{
		OpenIDURL:          viper.GetString("openid-provider.URL"),
		OpenIDClientID:     viper.GetString("openid-provider.client_id"),
		OpenIDClientSecret: viper.GetString("openid-provider.client_secret"),
		OpenIDRedirectURL:  viper.GetString("openid-provider.redirect_url"),
		DatabaseDialect:    viper.GetString("database.dialect"),
		DatabaseDSN:        viper.GetString("database.dsn"),
		Certificate:        viper.GetString("encryption.certificate"),
		PrivateKey:         viper.GetString("encryption.private_key"),
	}

	return cfg, nil
}

func (p *proxyConfig) EncryptionEnabled() bool {
	return !(p.Certificate == "" || p.PrivateKey == "")
}

func (p *proxyConfig) AuthenticationEnabled() bool {
	return !(p.OpenIDURL == "" || p.OpenIDClientID == "")
}

//Start starts the security gateway
func Start(bindingURL string, failure chan bool) {

	cfg, err := loadConfig()
	failure <- (err != nil)

	if err != nil {
		log.Error(err)
		return
	}

	provider, err := oidc.NewProvider(ctx, cfg.OpenIDURL)
	if err != nil {
		log.Error(err)
		return
	}

	oidcConfig := &oidc.Config{
		ClientID: cfg.OpenIDClientID,
	}
	verifier = provider.Verifier(oidcConfig)

	config = oauth2.Config{
		ClientID:     oidcConfig.ClientID,
		ClientSecret: cfg.OpenIDClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.OpenIDRedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	//http.Handle("/", proxify(addCORS()))

	err = http.ListenAndServeTLS(bindingURL, cfg.Certificate, cfg.PrivateKey, proxify())
	if err != nil {
		log.Error("ListenAndServe: ", err)
		return
	}
}
