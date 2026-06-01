/*
Copyright NetFoundry Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testutil

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	TestHome string     `json:"testHome"`
	Ziti     ZitiConfig `json:"ziti"`
	ZetA     ZetConfig  `json:"zetA"`
	ZetB     ZetConfig  `json:"zetB"`
	ZetC     ZetConfig  `json:"zetC"`
	IdP      IdPConfig  `json:"idp"`
}

type ZitiConfig struct {
	Binary   string `json:"binary"`
	URL      string `json:"url"`
	User     string `json:"user"`
	Password string `json:"password"`
}

type ZetConfig struct {
	Binary     string `json:"binary"`
	Verbosity  int    `json:"verbosity"`
	TlsuvDebug int    `json:"tlsuvDebug"`
}

type IdPConfig struct {
	UseTestHarnessIdP bool     `json:"useTestHarnessIdP"`
	Binary            string   `json:"binary"`
	Issuer            string   `json:"issuer"`
	SignerName        string   `json:"signerName"`
	ClientID          string   `json:"clientId"`
	ExtraClientIDs    []string `json:"extraClientIds"`
	Audience          string   `json:"audience"`
	Sub               string   `json:"sub"`
	Scopes            string   `json:"scopes"`
	User              IdPUser  `json:"user"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if c.ZetB.Binary == "" {
		c.ZetB.Binary = c.ZetA.Binary
	}
	if c.ZetC.Binary == "" {
		c.ZetC.Binary = c.ZetA.Binary
	}
	return &c, nil
}
