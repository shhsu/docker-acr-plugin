package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"net/url"

	"io/ioutil"

	"bufio"

	"github.com/Azure/go-autorest/autorest/adal"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spf13/cobra"
)

type loginOptions struct {
	ServerAddress string `json:"server-address,omitempty"`
	User          string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
}
type aadAuthResponse struct {
	RefreshToken string `json:"refresh_token"`
}

type accessTokenPayload struct {
	TenantID string `json:"tid"`
}

type authDirective struct {
	Service      string `json:"service"`
	Realm        string `json:"realm"`
	authEndpoint string
}

func (directive *authDirective) initialize() (err error) {
	if directive.Realm == "" {
		return fmt.Errorf("Www-Authenticate: realm not specified")
	}

	if directive.Service == "" {
		return fmt.Errorf("Www-Authenticate: service not specified")
	}

	var authURL *url.URL
	if authURL, err = url.Parse(directive.Realm); err != nil {
		return fmt.Errorf("Www-Authenticate: invalid realm %s", directive.Realm)
	}

	directive.authEndpoint = fmt.Sprintf("%s://%s/oauth2/exchange", authURL.Scheme, authURL.Host)
	return nil
}

var loginFailure *loginOptions
var useInputCreds *loginOptions

func getOAuthBaseURL() *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   "login.microsoftonline.com",
		Path:   "common/oauth2",
	}
}

func main() {
	var serverAddress, headerObject string
	cmd := &cobra.Command{
		Use:   "Azure Docker Registry Login Module",
		Short: "Azure Docker Registry Login Module",
		Long:  `A golang module that enable docker login via Azure Active Directory`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var directive authDirective
			var err error
			if err = json.Unmarshal([]byte(headerObject), &directive); err != nil {
				return err
			}
			if err = directive.initialize(); err != nil {
				return err
			}
			var result *loginOptions
			if result, err = login(serverAddress, &directive); err != nil {
				return err
			}

			var output []byte
			if output, err = json.Marshal(result); err != nil {
				return err
			}

			fmt.Print(string(output))
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&serverAddress, "serverAddress", "", "Registry login server")
	flags.StringVar(&headerObject, "headerObject", "", "Challenge header from the entry point")

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running subcommand: %s\n", err)
		os.Exit(-1)
	}
}

func login(serverAddress string, directive *authDirective) (*loginOptions, error) {
	var err error
	var adalToken *adal.Token
	if adalToken, err = interactiveLogin(); err != nil {
		return loginFailure, err
	}

	accessTokenEncoded := adalToken.AccessToken
	accessTokenSplit := strings.Split(accessTokenEncoded, ".")
	if len(accessTokenSplit) < 2 {
		return loginFailure, fmt.Errorf("invalid encoded id token: %s", accessTokenEncoded)
	}

	idPayloadEncoded := accessTokenSplit[1]
	var idJSON []byte
	if idJSON, err = jwt.DecodeSegment(idPayloadEncoded); err != nil {
		return loginFailure, fmt.Errorf("Error decoding accessToken: %s", err)
	}

	var accessToken accessTokenPayload
	if err := json.Unmarshal(idJSON, &accessToken); err != nil {
		return loginFailure, fmt.Errorf("Error unmarshalling id token: %s", err)
	}
	return getLoginOptions(serverAddress, directive, accessToken.TenantID, adalToken.RefreshToken)
}

func interactiveLogin() (*adal.Token, error) {
	oauthClient := &http.Client{}
	authEndpoint := getOAuthBaseURL()
	authEndpoint.Path = path.Join(authEndpoint.Path, "authorize")
	tokenEndpoint := getOAuthBaseURL()
	tokenEndpoint.Path = path.Join(tokenEndpoint.Path, "token")
	deviceCodeEndpoint := getOAuthBaseURL()
	deviceCodeEndpoint.Path = path.Join(deviceCodeEndpoint.Path, "devicecode")

	var err error
	var deviceCode *adal.DeviceCode
	if deviceCode, err = adal.InitiateDeviceAuth(
		oauthClient,
		adal.OAuthConfig{
			AuthorizeEndpoint:  *authEndpoint,
			TokenEndpoint:      *tokenEndpoint,
			DeviceCodeEndpoint: *deviceCodeEndpoint,
		},
		"38f45013-0177-45e8-a12e-124b191d8f63",
		"https://management.core.windows.net/"); err != nil {
		return nil, fmt.Errorf("Failed to start device auth flow: %s", err)
	}

	fmt.Fprintf(os.Stderr, "%s\n", *deviceCode.Message)
	var token *adal.Token
	if token, err = adal.WaitForUserCompletion(oauthClient, deviceCode); err != nil {
		return nil, fmt.Errorf("Failed to finish device auth flow: %s", err)
	}
	return token, nil
}

func getLoginOptions(
	serverAddress string,
	directive *authDirective,
	tenant string,
	refreshTokenEncoded string) (*loginOptions, error) {
	var err error
	data := url.Values{
		"service":       []string{directive.Service},
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{refreshTokenEncoded},
		"tenant":        []string{tenant},
	}

	client := &http.Client{}
	datac := data.Encode()
	r, _ := http.NewRequest("POST", directive.authEndpoint, bytes.NewBufferString(datac))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(datac)))

	var exchange *http.Response
	if exchange, err = client.Do(r); err != nil {
		return loginFailure, fmt.Errorf("Www-Authenticate: failed to reach auth url %s", directive.authEndpoint)
	}

	defer exchange.Body.Close()
	if exchange.StatusCode != 200 {
		return loginFailure, fmt.Errorf("Www-Authenticate: auth url %s responded with status code %d", directive.authEndpoint, exchange.StatusCode)
	}

	var content []byte
	if content, err = ioutil.ReadAll(exchange.Body); err != nil {
		return loginFailure, fmt.Errorf("Www-Authenticate: error reading response from %s", directive.authEndpoint)
	}

	var authResp aadAuthResponse
	if err = json.Unmarshal(content, &authResp); err != nil {
		return loginFailure, fmt.Errorf("Www-Authenticate: unable to read response %s", content)
	}

	return &loginOptions{
		ServerAddress: serverAddress,
		User:          "00000000-0000-0000-0000-000000000000",
		Password:      authResp.RefreshToken,
	}, nil
}

func invokeCmd(cmdStr string, args []string, forwardErr bool) ([]byte, error) {
	cmd := exec.Command(cmdStr, args...)

	var result bytes.Buffer
	cmd.Stdout = bufio.NewWriter(&result)
	if forwardErr {
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running: %s %s\n", cmdStr, strings.Join(args, " "))
		return []byte{}, err
	}

	return result.Bytes(), nil
}
