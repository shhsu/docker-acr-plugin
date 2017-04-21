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

var loginFailure *loginOptions

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

	// Acquire the device code
	if deviceCode, err := adal.InitiateDeviceAuth(
		oauthClient,
		adal.OAuthConfig{
			AuthorizeEndpoint:  *authEndpoint,
			TokenEndpoint:      *tokenEndpoint,
			DeviceCodeEndpoint: *deviceCodeEndpoint,
		},
		"04b07795-8ddb-461a-bbee-02f9e1bf7b46", // client id ---> copied from azure cli on python
		"https://management.core.windows.net/"); err != nil {
		return nil, fmt.Errorf("Failed to start device auth flow: %s", err)
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", *deviceCode.Message)
		// Wait here until the user is authenticated
		if token, err := adal.WaitForUserCompletion(oauthClient, deviceCode); err != nil {
			return nil, fmt.Errorf("Failed to finish device auth flow: %s", err)
		} else {
			return token, nil
		}
	}
}

func main() {
	var tenant, registry string
	cmd := &cobra.Command{
		Use:   "Azure Docker Registry Login Module",
		Short: "Azure Docker Registry Login Module",
		Long:  `A golang module that enable docker login via Azure Active Directory`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if result, err := login(tenant, registry); err != nil {
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
	flags.StringVar(&tenant, "tenantID", "", "Tenant ID, this parameter will be deprecated soon")
	flags.StringVar(&registry, "serverAddress", "", "Registry name")

	cmd.MarkFlagRequired("registry")

	if err := cmd.Execute(); err != nil {
		logrus.Errorf("Error running subcommand: %s\n", err)
		os.Exit(-1)
	}
}

func login(tenant string, registry string) (*loginOptions, error) {
	if registry == "" {
		return loginFailure, fmt.Errorf("please provide a docker registry name")
	}

	if adalToken, err := interactiveLogin(); err != nil {
		return loginFailure, err
	} else {
		authContent := map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": adalToken.RefreshToken,
		}
		if len(tenant) > 0 {
			authContent["tenant"] = tenant
		}
		return getLoginOptions(registry, &authContent)
	}
}

func getLoginOptions(serverAddress string, authContent *map[string]string) (*loginOptions, error) {
	challengeURL := url.URL{
		Scheme: "https",
		Host:   serverAddress,
		Path:   "v2/",
	}
	if challenge, err := http.Get(challengeURL.String()); err != nil {
		return loginFailure, fmt.Errorf("Error reaching registry endpoint %s", challengeURL.String())
	} else if authHeader, _ := challenge.Header["Www-Authenticate"]; challenge.StatusCode != 401 || len(authHeader) != 1 {
		return loginFailure,
			fmt.Errorf("Registry did not issue a valid AAD challenge, status: %d, authenticate header [%s]",
				challenge.StatusCode, strings.Join(authHeader, ", "))
	} else {
		tokens := strings.Split(authHeader[0], " ")
		if len(tokens) < 2 || strings.ToLower(tokens[0]) != "bearer" {
			return loginFailure, fmt.Errorf("Unexpected content in Www-Authenticate header: %s", authHeader[0])
		}

		var realm, service string
		for _, expr := range strings.Split(tokens[1], ",") {
			declaration := strings.SplitN(expr, "=", 2)
			if len(declaration) != 2 {
				logrus.Errorf("Invalid Syntax in Www-Authenticate header: %s", declaration)
				continue
			}
			k := strings.ToLower(strings.TrimSpace(declaration[0]))
			// might not be correct triming all quotes but we would just assume GIGO
			v := strings.Trim(strings.TrimSpace(declaration[1]), "\"")

			if k == "realm" {
				realm = v
			} else if k == "service" {
				service = v
			}
		}

		if realm == "" {
			return loginFailure, fmt.Errorf("Www-Authenticate: realm not specified")
		}

		if service == "" {
			return loginFailure, fmt.Errorf("Www-Authenticate: service not specified")
		}

		if authurl, err := url.Parse(realm); err != nil {
			return loginFailure, fmt.Errorf("Www-Authenticate: invalid realm %s", realm)
		} else {
			authEndpoint := fmt.Sprintf("%s://%s/oauth2/exchange", authurl.Scheme, authurl.Host)

			data := url.Values{
				"service": []string{service},
			}

			for k, v := range *authContent {
				data[k] = []string{v}
			}

			client := &http.Client{}
			datac := data.Encode()
			r, _ := http.NewRequest("POST", authEndpoint, bytes.NewBufferString(datac))
			r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Add("Content-Length", strconv.Itoa(len(datac)))

			if resp, err := client.Do(r); err != nil {
				return loginFailure, fmt.Errorf("Www-Authenticate: failed to reach auth url %s", authEndpoint)
			} else if resp.StatusCode != 200 {
				return loginFailure, fmt.Errorf("Www-Authenticate: auth url %s responded with status code %d", authEndpoint, resp.StatusCode)
			} else if content, err := ioutil.ReadAll(resp.Body); err != nil {
				return loginFailure, fmt.Errorf("Www-Authenticate: error reading response from %s", authEndpoint)
			} else {
				var authResp aadAuthResponse
				if err := json.Unmarshal(content, &authResp); err != nil {
					return loginFailure, fmt.Errorf("Www-Authenticate: unable to read response %s", content)
				} else {
					return &loginOptions{
						ServerAddress: serverAddress,
						User:          "00000000-0000-0000-0000-000000000000",
						Password:      authResp.RefreshToken,
					}, nil
				}
			}
		}
	}
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
