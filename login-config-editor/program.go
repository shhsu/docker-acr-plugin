package main

import (
	"fmt"
	"os"
	"runtime"

	"path"

	"io/ioutil"

	"encoding/json"

	"strings"

	"github.com/spf13/cobra"
)

type authConfig struct {
	Module string `json:"login-module"`
	Server string `json:"condition-server,omitempty"`
	Type   string `json:"condition-type,omitempty"`
	Realm  string `json:"condition-realm,omitempty"`
}

var force bool

func main() {
	var configFile, module, challengeType, server, realm string
	cmd := &cobra.Command{
		Use:   "Docker Login Config Editor",
		Short: "Configure docker to use different module for login.",
		Long:  "Configure docker to use different module for login.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(configFile) == 0 {
				configFile = path.Join(userHomeDir(), ".docker", "config.json")
			}
			if len(module) == 0 {
				return fmt.Errorf("Please specify a module name")
			}
			if len(challengeType) == 0 && len(server) == 0 && len(realm) == 0 {
				return fmt.Errorf("Please specify at least one of the following: challenge-type, challenge-realm, or server")
			}

			var err error
			var configObj map[string]interface{}

			if _, err = os.Stat(configFile); err != nil {
				if os.IsNotExist(err) {
					configObj = make(map[string]interface{})
				} else {
					return fmt.Errorf("Error trying to access config file: %s, err: %s", configFile, err)
				}
			} else {
				var bytes []byte
				if bytes, err = ioutil.ReadFile(configFile); err != nil {
					return fmt.Errorf("Error trying to read config file %s, err: %s", configFile, err)
				}
				if err = json.Unmarshal(bytes, &configObj); err != nil {
					return fmt.Errorf("Error trying to unmarshal config file %s, err: %s", configFile, err)
				}
			}

			existingConfigsRaw, found := configObj["registry-auth-config"]
			var existingConfigs []authConfig
			if !found {
				existingConfigs = []authConfig{}
			} else {
				var bytes []byte
				if bytes, err = json.Marshal(existingConfigsRaw); err != nil {
					return fmt.Errorf("Error trying to marshal configs back to bytes, err: %s", err)
				}
				if err = json.Unmarshal(bytes, &existingConfigs); err != nil {
					return fmt.Errorf("Error unmarshalling auth configurations, err: %s", err)
				}
			}

			for _, config := range existingConfigs {
				if strings.EqualFold(config.Module, module) &&
					strings.EqualFold(config.Server, server) &&
					strings.EqualFold(config.Type, challengeType) &&
					strings.EqualFold(config.Realm, realm) {
					fmt.Print("Found duplicate configuration in the config file, no operation would be done...")
					return nil
				}
			}

			existingConfigs = append(existingConfigs, authConfig{
				Module: module,
				Server: server,
				Type:   challengeType,
				Realm:  realm,
			})

			configObj["registry-auth-config"] = existingConfigs

			var bytes []byte
			if bytes, err = json.MarshalIndent(configObj, "", "\t"); err != nil {
				return fmt.Errorf("Error trying to marshal config object, err: %s", err)
			}

			var bakFileName = configFile + ".bak"
			if _, err = os.Stat(bakFileName); err == nil || !os.IsNotExist(err) {
				if err = promptForAbort("Please note that bak file will be overwritten, continue?"); err != nil {
					return err
				}
			}

			// NOTE: if any process created a bak file at this point by any chance, it would be overwritten
			if err = os.Rename(configFile, bakFileName); err != nil && !os.IsNotExist(err) {
				if err = promptForAbort("Unable to back up config file, continue?"); err != nil {
					return err
				}
			}

			if err = ioutil.WriteFile(configFile, bytes, 0644); err != nil {
				return fmt.Errorf("Error trying to write file to location %s, err: %s", configFile, err)
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&configFile, "config-file", "", "Location of the config file.")
	flags.StringVar(&module, "module", "", "Name of the login module to be used.")
	flags.StringVar(&server, "server", "", "Docker registry url to use this module.")
	flags.StringVar(&challengeType, "challenge-type", "", "Login challenge type required by this module.")
	flags.StringVar(&realm, "challenge-realm", "", "Login challenge realm required by this module.")
	flags.BoolVar(&force, "force", false, "Silently continue on warnings")

	cmd.MarkFlagRequired("module")

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running subcommand: %s\n", err)
		os.Exit(-1)
	}
}

func promptForAbort(msg string) error {
	if force {
		return nil
	}

	fmt.Printf("%s [Y/y]", msg)
	var ans string
	var err error
	if _, err = fmt.Scanf("%s", &ans); err != nil {
		return fmt.Errorf("Unable to get user input")
	}
	if !strings.EqualFold(ans, "y") {
		return fmt.Errorf("User aborted")
	}
	return nil
}

func userHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}
