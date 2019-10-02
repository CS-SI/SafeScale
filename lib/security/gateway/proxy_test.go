package gateway_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/security/model"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/websocket"
	"golang.org/x/oauth2"

	"github.com/CS-SI/SafeScale/lib/security/gateway"
	"github.com/stretchr/testify/assert"
)

func Clean() {
	db := model.NewDataAccess("sqlite3", "/tmp/safe-security.db").Get()
	defer func() {
		_ = db.Close()
	}()
	db.DropTableIfExists(&model.Service{}, &model.Role{}, &model.AccessPermission{}, &model.User{})
}
func runTestService() {
	da := model.NewDataAccess("sqlite3", "/tmp/safe-security.db")
	db := da.Get().Debug()
	defer func() {
		_ = db.Close()
	}()
	db.AutoMigrate(&model.Service{}, &model.Role{}, &model.AccessPermission{}, &model.User{})

	srv1 := model.Service{
		BaseURL: "http://localhost:10000/date",
		Name:    "TEST",
	}
	if err := db.Create(&srv1).Error; err != nil {
		log.Fatal()
	}

	usr1 := model.User{
		Email: "user@c-s.fr",
	}
	if err := db.Create(&usr1).Error; err != nil {
		log.Fatal(err)
	}
	perm1 := model.AccessPermission{
		Action:          "GET",
		ResourcePattern: "*",
	}

	if err := db.Create(&perm1).Error; err != nil {
		log.Fatal(err)
	}

	role1 := model.Role{
		Name: "USER",
	}

	if err := db.Create(&role1).Error; err != nil {
		log.Fatal(err)
	}
	if err := db.Model(&role1).Association("AccessPermissions").Append(perm1).Error; err != nil {
		log.Fatal(err)
	}

	if err := db.Model(&srv1).Association("Roles").Append(role1).Error; err != nil {
		log.Fatal(err)
	}

	if err := db.Model(&usr1).Association("Roles").Append(role1).Error; err != nil {
		log.Fatal(err)
	}

	srv2 := model.Service{
		BaseURL: "ws://localhost:10000/date",
		Name:    "TESTWS",
	}
	if err := db.Create(&srv2).Error; err != nil {
		log.Fatal()
	}
	perm2 := model.AccessPermission{
		Action:          "WS",
		ResourcePattern: "*",
	}

	if err := db.Create(&perm2).Error; err != nil {
		log.Fatal(err)
	}

	if err := db.Model(&srv2).Association("Roles").Append(role1).Error; err != nil {
		log.Fatal(err)
	}

	if err := db.Model(&role1).Association("AccessPermissions").Append(perm2).Error; err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	var upgrader = websocket.Upgrader{} // use default options

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if websocket.IsWebSocketUpgrade(r) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			}
			go func() {
				defer func() {
					_ = conn.Close()
				}()
				for i := 0; i < 10; i++ {
					now := time.Now()
					text, _ := now.MarshalText()
					_ = conn.WriteMessage(websocket.TextMessage, text)
					time.Sleep(temporal.GetMinDelay())
				}

			}()
		}
		now := time.Now()
		text, _ := now.MarshalText()
		dump, err := httputil.DumpRequest(r, true)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s", dump)
		_, _ = w.Write(text)
	})
	_ = http.ListenAndServe(":10000", mux)

}

func getUserToken() string {
	provider, _ := oidc.NewProvider(context.Background(), "http://localhost:8080/auth/realms/master")

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     "safescale",
		ClientSecret: "safescale",
		RedirectURL:  "",

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	token, err := oauth2Config.PasswordCredentialsToken(context.Background(), "user", "user")
	if err != nil {
		return ""
	}
	return token.AccessToken

}

func TestGateway(t *testing.T) {
	Clean()

	beauty := make(chan bool)
	go gateway.Start(":4443", beauty)
	failed := <-beauty

	if failed {
		t.Skip()
	}

	go runTestService()
	time.Sleep(2 * time.Second)
	resp, err := http.Get("http://localhost:10000/date")
	assert.Nil(t, err)
	text, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	fmt.Println(string(text))

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	token := getUserToken()
	req, err := http.NewRequest("GET", "https://localhost:4443/TEST", nil)
	assert.Nil(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := http.Client{}
	resp, err = client.Do(req)
	assert.Nil(t, err)
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(dump))

	websocket.DefaultDialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	header := http.Header{}
	header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	ws, _, err := websocket.DefaultDialer.Dial("wss://localhost:4443/TESTWS", header)
	assert.Nil(t, err)

	for i := 0; i < 10; i++ {
		_, buffer, err := ws.ReadMessage()
		assert.Nil(t, err)
		println(string(buffer))
	}
	_ = ws.Close()
}
