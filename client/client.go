package client

import (
	// "bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

type OneLoginClient struct {
	baseURL          *url.URL
	httpClient       *http.Client
	initialAuthToken string
}

type AuthRequest struct {
	State   string             `json:"state,omitempty"`
	Return  string             `json:"return,omitempty"`
	Payload AuthRequestPayload `json:"payload"`
}

type AuthRequestPayload struct {
	Login    string `json:"login,omitempty"`
	Password string `json:"password,omitempty"`
	Jwt      string `json:"jwt,omitempty"`

	RemberUsername  *bool `json:"remember_username,omitempty"`
	RememberBrowser *bool `json:"remember_browser,omitempty"`
	KeepMeSignedIn  *bool `json:"keep_me_signed_in,omitempty"`
}

type MFAVerificationRequest struct {
	DeviceID    string `json:"device_id,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
}

type MFAOTPRequest struct {
	OTP string `json:"otp,omitempty"`
}

type AuthResponse struct {
	Action           string `json:"action"`
	StateMachineName string `json:"state_machine_name"`
	Error            string
	Context          AuthResponseContext `json:context`
	MFA              AuthResponseContext `json:"mfa"`
}

type AuthResponseContext struct {
	Jwt string `json:"jwt"`
}

type MFAResponse struct {
	Jwt string `json:"jwt"`
}

type MFADevice struct {
	ID         string `json:"id"`
	TypeID     int    `json:"type_id"`
	FactorName string `json:"factor_name"`
	Default    bool   `json:"default"`
}

type MFAVerifcationResponse struct {
	ID     string `json:"id"`
	Jwt    string `json:"jwt"`
	Status string `json:"status"`
}

func NewClient(endpoint string) (client *OneLoginClient, err error) {
	endpoint = strings.TrimSuffix(endpoint, "/")
	baseobj, _ := url.Parse(endpoint)
	jar, _ := cookiejar.New(&cookiejar.Options{})

	client = &OneLoginClient{
		baseURL: baseobj,
		httpClient: &http.Client{
			// keep track of cookies
			Jar: jar,
			// don't follow redirects
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		},
	}

	// initial request, get return value from query string
	resp, err := client.get("/login")
	if err != nil {
		return client, fmt.Errorf("Unable to GET /login: %s", err)
	}
	if resp.StatusCode != 302 {
		return client, fmt.Errorf("Unexpected Status Code from /login: %d", resp.StatusCode)
	}

	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return client, fmt.Errorf("Error parsing /login response: %s", err)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return client, fmt.Errorf("Error parsing /login response: %s", err)
	}
	if len(q["return"]) == 0 {
		return client, errors.New(`Couldn't find "return" value in login response`)
	}

	client.initialAuthToken = q["return"][0]
	return
}

func (c *OneLoginClient) SamlAssertionForApp(appid string) (samlAssertion string, err error) {
	resp, err := c.get(fmt.Sprintf("/trust/saml2/launch/%s", appid))
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Unexpected response code from SAML endpoint: %d\n", resp.StatusCode)
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return
	}
	samlAssertion, ok := doc.Find(`input[name="SAMLResponse"]`).First().Attr("value")
	if !ok {
		return "", errors.New("SAML Assertion not found in response")
	}

	return
}

func (c *OneLoginClient) Login(username string, password string, otp string) (err error) {
	// start a new auth flow
	authresp, err := c.authStart()

	// keep making requests to their state
StateLoop:
	for {
		// if the prior request errored out, or isn't for the auth state machine
		// then bail
		if err != nil {
			return err
		}
		if authresp.StateMachineName != "auth" {
			err = fmt.Errorf("Unexpected State Machine: %s", authresp.StateMachineName)
		}

		// do the needful based on what step they told us we are in
		switch authresp.Action {
		case "username":
			authresp, err = c.authUsername(username, authresp)
		case "password":
			authresp, err = c.authPassword(password, authresp)
		case "mfa_login":
			authresp, err = c.authMFA(otp, authresp)
		case "remember_browser":
			authresp, err = c.authRemeberBrowser(authresp)
		case "success":
			break StateLoop
		default:
			err = fmt.Errorf("Received unsupported action: %s ", authresp.Action)
		}
	}

	return nil
}

func decodeAuthResponse(body io.Reader) (*AuthResponse, error) {
	var authresp AuthResponse
	err := json.NewDecoder(body).Decode(&authresp)
	if err != nil {
		return nil, err
	}
	if authresp.Error != "" {
		return &authresp, errors.New(authresp.Error)
	} else {
		return &authresp, nil
	}
}

func decodeMFAResponse(body io.Reader) (*MFAResponse, error) {
	var mfaresp MFAResponse
	err := json.NewDecoder(body).Decode(&mfaresp)
	if err != nil {
		return nil, err
	}
	return &mfaresp, nil
}

func decodeMFADeviceResponse(body io.Reader) (selectedDevice *MFADevice, err error) {
	var devices []*MFADevice
	err = json.NewDecoder(body).Decode(&devices)
	if err != nil {
		return nil, err
	}

	//select device
	for _, d := range devices {
		// grab the first authenticator device we see, unless there's a later authenticator device that's flagged default
		if d.FactorName == "Authenticator" && (selectedDevice == nil || (d.Default == true && selectedDevice.Default == false)) {
			selectedDevice = d
		}
	}
	if selectedDevice == nil {
		return nil, fmt.Errorf("Failed to find an authenticator mfa device: %+v", devices)
	}

	return
}

func decodeMFAVerificationResponse(body io.Reader) (*MFAVerifcationResponse, error) {
	var vresp MFAVerifcationResponse
	err := json.NewDecoder(body).Decode(&vresp)
	if err != nil {
		return nil, err
	}

	return &vresp, nil

}

func (c *OneLoginClient) authStart() (*AuthResponse, error) {
	body, err := json.Marshal(&AuthRequest{Return: c.initialAuthToken})
	if err != nil {
		return nil, err
	}
	resp, err := c.post("/access/auth", "", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return decodeAuthResponse(resp.Body)
}

func (c *OneLoginClient) authUsername(username string, lastresp *AuthResponse) (*AuthResponse, error) {
	r := false
	body, err := json.Marshal(&AuthRequest{State: "username", Payload: AuthRequestPayload{Login: username, RemberUsername: &r}})
	if err != nil {
		return nil, err
	}

	resp, err := c.put("/access/auth", lastresp.Context.Jwt, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return decodeAuthResponse(resp.Body)
}

func (c *OneLoginClient) authPassword(password string, lastresp *AuthResponse) (*AuthResponse, error) {
	l := false
	body, err := json.Marshal(&AuthRequest{State: "password", Payload: AuthRequestPayload{Password: password, KeepMeSignedIn: &l}})
	if err != nil {
		return nil, err
	}
	resp, err := c.put("/access/auth", lastresp.Context.Jwt, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return decodeAuthResponse(resp.Body)
}

func (c *OneLoginClient) authMFA(otp string, lastresp *AuthResponse) (*AuthResponse, error) {
	// start MFA auth subprocess
	resp, err := c.getJSON("/mfa/v1/auth", lastresp.MFA.Jwt)
	if err != nil {
		return nil, err
	}
	mfaresp, err := decodeMFAResponse(resp.Body)
	if err != nil {
		return nil, err
	}
	if mfaresp.Jwt == "" {
		return nil, fmt.Errorf("Unexpected MFA Start Response: %+v", mfaresp)
	}

	// list available MFA devices
	resp, err = c.getJSON("/mfa/v1/devices", mfaresp.Jwt)
	if err != nil {
		return nil, err
	}
	selectedDevice, err := decodeMFADeviceResponse(resp.Body)
	if err != nil {
		return nil, err
	}

	// start validation
	body, err := json.Marshal(&MFAVerificationRequest{DeviceID: selectedDevice.ID, AccessToken: mfaresp.Jwt})
	if err != nil {
		return nil, err
	}
	resp, err = c.post("/mfa/v1/verifications", mfaresp.Jwt, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	vresp, err := decodeMFAVerificationResponse(resp.Body)
	if err != nil {
		return nil, err
	}
	if vresp.ID == "" || vresp.Status != "pending" {
		return nil, fmt.Errorf("Unexpected Validation Start Response: %+v", vresp)
	}

	// complete validation
	body, err = json.Marshal(&MFAOTPRequest{OTP: otp})
	if err != nil {
		return nil, err
	}
	resp, err = c.put(fmt.Sprintf("/mfa/v1/verifications/%s", vresp.ID), mfaresp.Jwt, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	vresp, err = decodeMFAVerificationResponse(resp.Body)
	if vresp.ID == "" || vresp.Status != "accepted" {
		return nil, fmt.Errorf("Unexpected Validation Complete Response: %+v", vresp)
	}

	// tell the auth state machine about the MFA completion
	body, err = json.Marshal(&AuthRequest{State: "mfa_login", Payload: AuthRequestPayload{Jwt: vresp.Jwt}})
	if err != nil {
		return nil, err
	}
	resp, err = c.put("/access/auth", lastresp.Context.Jwt, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return decodeAuthResponse(resp.Body)
}

func (c *OneLoginClient) authRemeberBrowser(lastresp *AuthResponse) (*AuthResponse, error) {
	l := false
	body, err := json.Marshal(&AuthRequest{State: "remember_browser", Payload: AuthRequestPayload{RememberBrowser: &l}})
	if err != nil {
		return nil, err
	}
	resp, err := c.put("/access/auth", lastresp.Context.Jwt, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	return decodeAuthResponse(resp.Body)
}

func (c *OneLoginClient) absoluteURL(uri string) string {
	if !strings.HasPrefix(uri, c.baseURL.String()) {
		uri = c.baseURL.String() + "/" + strings.TrimPrefix(uri, "/")
	}

	return uri
}

func (c *OneLoginClient) doRequest(method string, uri string, authToken string, json bool, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest(method, c.absoluteURL(uri), body)
	if err != nil {
		return
	}
	if authToken != "" {
		req.Header.Set("authorization", fmt.Sprintf("Bearer %s", authToken))
	}

	if json {
		req.Header.Set("content-type", "application/json")
		req.Header.Set("accept", "application/json")
	}

	return c.httpClient.Do(req)
}

func (c *OneLoginClient) post(uri string, authToken string, body io.Reader) (resp *http.Response, err error) {
	return c.doRequest(http.MethodPost, uri, authToken, true, body)
}

func (c *OneLoginClient) put(uri string, authToken string, body io.Reader) (resp *http.Response, err error) {
	return c.doRequest(http.MethodPut, uri, authToken, true, body)
}

func (c *OneLoginClient) get(uri string) (resp *http.Response, err error) {
	return c.doRequest(http.MethodGet, uri, "", false, nil)
}

func (c *OneLoginClient) getJSON(uri string, authToken string) (resp *http.Response, err error) {
	return c.doRequest(http.MethodGet, uri, authToken, true, nil)
}
