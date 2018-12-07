package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	log "github.com/sirupsen/logrus"
)

//KeyCloak class to manage KeyCloak admin API
type KeyCloak struct {
	BaseURL   string
	Realm     string
	Usernamme string
	Password  string
}

//KeyCloakAdminToken KeyCloak administration token structure
type KeyCloakAdminToken struct {
	AccessToken      string `json:"access_token,omitempty"`
	ExpiresIn        uint   `json:"expires_in,omitempty"`
	RefreshExpiresIn uint   `json:"refresh_expires_in,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	NotBeforePolicy  uint   `json:"not-before-policy,omitempty"`
	SessionState     string `json:"session_state,omitempty"`
	Scope            string `json:"scope,omitempty"`
}

//KeyCloackClient defines a KeyCloak client
type KeyCloackClient struct {
	ClientID                  string   `json:"clientId,omitempty"`
	Secret                    string   `json:"secret,omitempty"`
	Name                      string   `json:"name,omitempty"`
	Enabled                   bool     `json:"enabled,omitempty"`
	PublicClient              bool     `json:"publicClient,omitempty"`
	Protocol                  string   `json:"protocol,omitempty"`
	DirectAccessGrantsEnabled bool     `json:"directAccessGrantsEnabled,omitempty"`
	StandardFlowEnabled       bool     `json:"standardFlowEnabled,omitempty"`
	RedirectURIs              []string `json:"redirectUris,omitempty"`
}

//GetAccessToken get keycloak admin api access token
func (kc *KeyCloak) GetAccessToken() (string, error) {
	tokens := []string{"auth/realms", kc.Realm, "protocol/openid-connect/token", "/"}
	resource := strings.Join(tokens, "/")
	apiURL := kc.BaseURL
	data := url.Values{}
	data.Set("username", kc.Usernamme)
	data.Set("password", kc.Password)
	data.Set("grant_type", "password")
	data.Set("client_id", "admin-cli")

	u, _ := url.ParseRequestURI(apiURL)
	u.Path = resource
	urlStr := u.String()

	client := &http.Client{}
	r, _ := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode())) // URL-encoded payload
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	resp, err := client.Do(r)
	if err != nil {
		return "", err
	}
	body := resp.Body
	defer func() {
		clErr := body.Close()
		if clErr != nil {
			log.Error(clErr)
		}
	}()
	buffer, err := ioutil.ReadAll(body)
	if err != nil {
		return "", err
	}
	token := KeyCloakAdminToken{}
	err = json.Unmarshal(buffer, &token)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

//CreateClientApplication create a client application
func (kc *KeyCloak) CreateClientApplication(clientID, clientSecret, clientName string) error {
	token, err := kc.GetAccessToken()
	tokens := []string{"auth/realms", kc.Realm, "protocol/openid-connect/token", "/"}
	resource := strings.Join(tokens, "/")
	apiURL := kc.BaseURL

	u, _ := url.ParseRequestURI(apiURL)
	u.Path = resource
	urlStr := u.String()

	client := KeyCloackClient{
		ClientID:                  clientID,
		Secret:                    clientSecret,
		Name:                      clientName,
		Enabled:                   true,
		PublicClient:              true,
		Protocol:                  "openid-connect",
		DirectAccessGrantsEnabled: true,
		StandardFlowEnabled:       true,
		RedirectURIs:              []string{"http://localhost:8080"},
	}

	httpClt := &http.Client{}
	b := new(bytes.Buffer)
	nerr := json.NewEncoder(b).Encode(client)
	if nerr != nil {
		log.Warnf("Problem encoding: %v", nerr)
	}
	r, _ := http.NewRequest("POST", urlStr, b)
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Accept", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(b.Len()))
	r.Header.Add("Authorization", fmt.Sprintf("Bearer %v", token))
	resp, err := httpClt.Do(r)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf(resp.Status)

}

//KeyCloackUser defines a KeyCloak user
type KeyCloackUser struct {
	ID                         string                   `json:"id,omitempty"`
	Origin                     string                   `json:"origin,omitempty"`
	CreatedTimestamp           uint64                   `json:"createdTimestamp,omitempty"`
	Username                   string                   `json:"username,omitempty"`
	Enabled                    bool                     `json:"enabled,omitempty"`
	EmailVerified              bool                     `json:"emailVerified,omitempty"`
	FirstName                  string                   `json:"firstName,omitempty"`
	LastName                   string                   `json:"lastName,omitempty"`
	Email                      string                   `json:"email,omitempty"`
	FederationLink             string                   `json:"federationLink,omitempty"`
	ServiceAccountClientID     string                   `json:"serviceAccountClientId,omitempty"`
	Attributes                 map[string]string        `json:"attributes,omitempty"`
	Credentials                []map[string]interface{} `json:"credentials,omitempty"`
	DisableableCredentialTypes []string                 `json:"disableableCredentialTypes,omitempty"`
	RequiredActions            []string                 `json:"requiredActions,omitempty"`
	FederatedIdentities        []map[string]interface{} `json:"federatedIdentities,omitempty"`
	RealmRoles                 []string                 `json:"realmRoles,omitempty"`
	ClientRoles                map[string]string        `json:"clientRoles,omitempty"`
	ClientConsents             []map[string]interface{} `json:"clientConsents,omitempty"`
	Groups                     []string                 `json:"groups,omitempty"`
}

func newKeyCloackUser(name, email string, attrs map[string]interface{}) map[string]interface{} {
	user := make(map[string]interface{})
	user["email"] = email
	user["username"] = name
	for k, v := range attrs {
		user[k] = v
	}
	return user
}

//CreateUser create a user
func (kc *KeyCloak) CreateUser(name, email string, attrs map[string]interface{}) error {
	token, err := kc.GetAccessToken()
	tokens := []string{"admin/realms", kc.Realm, "users", "/"}
	resource := strings.Join(tokens, "/")
	apiURL := kc.BaseURL

	u, _ := url.ParseRequestURI(apiURL)
	u.Path = resource
	urlStr := u.String()

	httpClt := &http.Client{}
	b := new(bytes.Buffer)
	nerr := json.NewEncoder(b).Encode(newKeyCloackUser(name, email, attrs))
	if nerr != nil {
		log.Warnf("Problem encoding: %v", nerr)
	}
	r, _ := http.NewRequest("POST", urlStr, b)
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Accept", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(b.Len()))
	r.Header.Add("Authorization", fmt.Sprintf("Bearer %v", token))
	resp, err := httpClt.Do(r)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf(resp.Status)
}
