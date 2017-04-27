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
	"syscall"

	"net/url"

	"io/ioutil"

	"bufio"

	"github.com/Sirupsen/logrus"
	"github.com/cosmincojocar/adal"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spf13/cobra"
)

type loginOptions struct {
	ServerAddress string `json:"serverAddress,omitempty"`
	User          string `json:"user,omitempty"`
	Password      string `json:"password,omitempty"`
}
type aadAuthResponse struct {
	RefreshToken string `json:"refresh_token"`
}

type idTokenPayload struct {
	TenantID string `json:"tid"`
}

type aadAuthArgs struct {
	authEndpoint string
	service      string
	realm        string
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
		"04b07795-8ddb-461a-bbee-02f9e1bf7b46", // client id ---> copied from azure cli on python
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

func main() {
	var registry, username, password string
	cmd := &cobra.Command{
		Use:   "Azure Docker Registry Login Module",
		Short: "Azure Docker Registry Login Module",
		Long:  `A golang module that enable docker login via Azure Active Directory`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if result, err := login(registry, username, password); err != nil {
				return err
			} else if output, err := json.Marshal(result); err != nil {
				return err
			} else {
				fmt.Print(string(output))
				return nil
			}
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&registry, "serverAddress", "", "Registry name")
	flags.StringVar(&username, "username", "", "username") // not used
	flags.StringVar(&password, "password", "", "password") // not used

	cmd.MarkFlagRequired("registry")

	if err := cmd.Execute(); err != nil {
		logrus.Errorf("Error running subcommand: %s\n", err)
		os.Exit(-1)
	}
}

func login(registry string, username string, password string) (*loginOptions, error) {
	if registry == "" {
		return loginFailure, fmt.Errorf("please provide a docker registry name")
	}

	// respect the username and password the user passed in
	if username != "" || password != "" {
		return &loginOptions{
			User:          username,
			Password:      password,
			ServerAddress: registry,
		}, nil
	}

	var err error
	var aadArgs *aadAuthArgs
	if aadArgs, err = getAADEntryPoint(registry); err != nil {
		return loginFailure, err
	} else if aadArgs == nil {
		return &loginOptions{
			ServerAddress: registry,
		}, nil
	}

	var adalToken *adal.Token
	if adalToken, err = interactiveLogin(); err != nil {
		return loginFailure, err
	}

	idTokenEncoded := adalToken.IDToken
	idTokenSplit := strings.Split(idTokenEncoded, ".")
	if len(idTokenSplit) < 2 {
		return loginFailure, fmt.Errorf("invalid encoded id token: %s", idTokenEncoded)
	}

	idPayloadEncoded := idTokenSplit[1]
	var idJSON []byte
	if idJSON, err = jwt.DecodeSegment(idPayloadEncoded); err != nil {
		return loginFailure, fmt.Errorf("Error decoding idToken: %s", err)
	}

	var idToken idTokenPayload
	if err := json.Unmarshal(idJSON, &idToken); err != nil {
		return loginFailure, fmt.Errorf("Error unmarshalling id token: %s", err)
	}
	return getLoginOptions(registry, aadArgs, idToken.TenantID, adalToken.RefreshToken)
}

func getAADEntryPoint(registry string) (*aadAuthArgs, error) {
	challengeURL := url.URL{
		Scheme: "https",
		Host:   registry,
		Path:   "v2/",
	}
	var err error
	var challenge *http.Response
	if challenge, err = http.Get(challengeURL.String()); err != nil {
		return nil, fmt.Errorf("Error reaching registry endpoint %s", challengeURL.String())
	}
	defer challenge.Body.Close()

	if challenge.StatusCode != 401 {
		return nil, fmt.Errorf("Registry did not issue a valid AAD challenge, status: %d", challenge.StatusCode)
	}

	var authHeader []string
	var ok bool
	if authHeader, ok = challenge.Header["Www-Authenticate"]; !ok {
		return nil, fmt.Errorf("Challenge response does not contain header 'Www-Authenticate'")
	}

	if len(authHeader) != 1 {
		return nil, fmt.Errorf("Registry did not issue a valid AAD challenge, authenticate header [%s]",
			strings.Join(authHeader, ", "))
	}

	configSections := strings.SplitN(authHeader[0], " ", 2)
	authType := strings.ToLower(configSections[0])
	if authType != "bearer" {
		// unable to resolve username or password because it's not expected auth type, hand the authentication
		// back to docker
		return nil, nil
	}

	authParams := configSections[1]
	var realm, service string
	for _, expr := range strings.Split(authParams, ",") {
		declaration := strings.SplitN(expr, "=", 2)
		if len(declaration) != 2 {
			logrus.Errorf("Invalid Syntax in Www-Authenticate header: %s", declaration)
			continue
		}
		k := strings.ToLower(strings.TrimSpace(declaration[0]))
		v := strings.Trim(strings.TrimSpace(declaration[1]), "\"")
		if k == "realm" {
			realm = v
		} else if k == "service" {
			service = v
		}
	}

	if realm == "" {
		return nil, fmt.Errorf("Www-Authenticate: realm not specified")
	}

	if service == "" {
		return nil, fmt.Errorf("Www-Authenticate: service not specified")
	}

	var authURL *url.URL
	if authURL, err = url.Parse(realm); err != nil {
		return nil, fmt.Errorf("Www-Authenticate: invalid realm %s", realm)
	}

	return &aadAuthArgs{
		realm:        realm,
		service:      service,
		authEndpoint: fmt.Sprintf("%s://%s/oauth2/exchange", authURL.Scheme, authURL.Host),
	}, nil
}

func getLoginOptions(
	serverAddress string,
	aadArgs *aadAuthArgs,
	tenant string,
	refreshTokenEncoded string) (*loginOptions, error) {
	var err error
	data := url.Values{
		"service":       []string{aadArgs.service},
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{refreshTokenEncoded},
		"tenant":        []string{tenant},
	}

	client := &http.Client{}
	datac := data.Encode()
	r, _ := http.NewRequest("POST", aadArgs.authEndpoint, bytes.NewBufferString(datac))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(datac)))

	var exchange *http.Response
	if exchange, err = client.Do(r); err != nil {
		return loginFailure, fmt.Errorf("Www-Authenticate: failed to reach auth url %s", aadArgs.authEndpoint)
	}

	defer exchange.Body.Close()
	if exchange.StatusCode != 200 {
		return loginFailure, fmt.Errorf("Www-Authenticate: auth url %s responded with status code %d", aadArgs.authEndpoint, exchange.StatusCode)
	}

	var content []byte
	if content, err = ioutil.ReadAll(exchange.Body); err != nil {
		return loginFailure, fmt.Errorf("Www-Authenticate: error reading response from %s", aadArgs.authEndpoint)
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
		exitCode := "(None)"
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = string(exitError.Sys().(syscall.WaitStatus).ExitCode)
		}
		logrus.Errorf("Error running: %s %s, exit code: %s\n", cmdStr, strings.Join(args, " "), exitCode)
		return []byte{}, err
	}

	return result.Bytes(), nil
}
