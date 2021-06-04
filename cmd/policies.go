/*
Copyright © 2021 JEFFREY AVEN jeffrey.aven@gammadata.io

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// policiesCmd represents the policies command
var policiesCmd = &cobra.Command{
	Use:   "policies",
	Short: "The Okta Policy API enables an Administrator to perform Policy and Policy Rule operations.",
	Long: `
	The Okta Policy API enables an Administrator to perform Policy and Policy Rule operations. For example:

okta-admin policies list
okta-admin policies create
	`,
	Args: cobra.MinimumNArgs(1),
}

//
// Types
//
type IDPDiscoveryPolicyRule struct {
	Name       string `json:"name"`
	Priority   int    `json:"priority"`
	Status     string `json:"status"`
	Type       string `json:"type"`
	Conditions struct {
		Network struct {
			Connection string `json:"connection"`
		} `json:"network"`
		Platform struct {
			Include []struct {
				Type string `json:"type"`
				Os   struct {
					Type string `json:"type"`
				} `json:"os"`
			} `json:"include"`
			Exclude []interface{} `json:"exclude"`
		} `json:"platform"`
		UserIdentifier struct {
			Patterns []interface{} `json:"patterns"`
		} `json:"userIdentifier"`
		App struct {
			Include []struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"include"`
			Exclude []interface{} `json:"exclude"`
		} `json:"app"`
	} `json:"conditions"`
	Actions struct {
		Idp struct {
			Providers []struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"providers"`
		} `json:"idp"`
	} `json:"actions"`
}

//
// Output Operations (return data)
//

// okta-admin policies list <type>
var listPoliciesCmd = &cobra.Command{
	Use:   "list <policyType>",
	Short: "Lists policies in your organization by type.",
	Long: `Lists policies in your organization by type.
Valid policyTypes include OKTA_SIGN_ON, PASSWORD, MFA_ENROLL, OAUTH_AUTHORIZATION_POLICY, IDP_DISCOVERY`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		policyType := args[0]
		queryParams := query.NewQueryParams(query.WithType(policyType))
		log.Printf("Listing policies in %s", viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Policy.ListPolicies(ctx, queryParams))
	},
}

// okta-admin policies listrules <policyId>
var listPolicyRulesCmd = &cobra.Command{
	Use:   "listrules <policyId>",
	Short: "Enumerates all policy rules.",
	Long:  `Enumerates all policy rules.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		policyId := args[0]
		log.Printf("Listing rules for policy %s in %s", policyId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Policy.ListPolicyRules(ctx, policyId))
	},
}

// okta-admin policies get <policyId>
var getPolicyCmd = &cobra.Command{
	Use:   "get <policyId>",
	Short: "Gets a policy.",
	Long:  `Gets a policy.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		policyId := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Getting policy %s in %s", policyId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Policy.GetPolicy(ctx, policyId, queryParams))
	},
}

// okta-admin policies getrule <policyId> <ruleId>
var getPolicyRuleCmd = &cobra.Command{
	Use:   "getrule <policyId> <ruleId>",
	Short: "Gets a policy rule.",
	Long:  `Gets a policy rule.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		policyId := args[0]
		ruleId := args[1]
		log.Printf("Getting rule %s for policy %s in %s", ruleId, policyId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Policy.GetPolicyRule(ctx, policyId, ruleId))
	},
}

// okta-admin policies createrule <policyId> <jsonBody>
var createPolicyRuleCmd = &cobra.Command{
	Use:   "createrule <policyId> <jsonBody>",
	Short: "Creates a policy rule.",
	Long:  `Creates a policy rule.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		policyId := args[0]
		jsonBody := args[1]
		var body okta.PolicyRule
		json.Unmarshal([]byte(jsonBody), &body)
		log.Printf("Creating rules for policy %s in %s", policyId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Policy.CreatePolicyRule(ctx, policyId, body))
	},
}

// okta-admin policies usemsftidpforapp <IdpDiscoveryPolicyId> <msftIdpId> <appId>
var createMsftIdPforAppPolicyCmd = &cobra.Command{
	Use:   "usemsftidpforapp <IdpDiscoveryPolicyId> <msftIdpId> <appId>",
	Short: "Creates a policy to use a MSFT IdP for a given application.",
	Long:  `Creates a policy to use a MSFT IdP for a given application.`,
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		IdpDiscoveryPolicyId := args[0]
		msftIdpId := args[1]
		appId := args[2]
		policyRule := IDPDiscoveryPolicyRule{}
		data := `
		{
			"name": "Use MSFT IDP",
			"priority": 1,
			"status": "ACTIVE",
			"type": "IDP_DISCOVERY",
			"conditions": {
			  "network": {
				"connection": "ANYWHERE"
			  },
			  "platform": {
				"include": [
				  {
					"type": "ANY",
					"os": {
					  "type": "ANY"
					}
				  }
				],
				"exclude": []
			  },
			  "userIdentifier": {
				"patterns": []
			  },
			  "app": {
				"include": [
				  {
					"type": "APP",
					"id": ""
				  }
				],
				"exclude": []
			  }
			},
			"actions": {
			  "idp": {
				"providers": [
				  {
					"type": "MICROSOFT",
					"id": ""
				  }
				]
			  }
			}
		  }
		`
		json.Unmarshal([]byte(data), &policyRule)
		policyRule.Actions.Idp.Providers[0].ID = msftIdpId
		policyRule.Conditions.App.Include[0].ID = appId
		var jsonData []byte
		jsonData, err := json.Marshal(policyRule)
		if err != nil {
			log.Println(err)
		}
		//log.Println(string(jsonData))
		url := fmt.Sprintf("/api/v1/policies/%s/rules", IdpDiscoveryPolicyId)
		processHttpOutput(url, jsonData)
	},
}

/* policy client.Policy
ActivatePolicy
ActivatePolicyRule
DeactivatePolicy
DeactivatePolicyRule
DeletePolicy
DeletePolicyRule
UpdatePolicy
UpdatePolicyRule
*/

func init() {
	rootCmd.AddCommand(policiesCmd)
	policiesCmd.AddCommand(listPoliciesCmd)
	policiesCmd.AddCommand(listPolicyRulesCmd)
	policiesCmd.AddCommand(getPolicyRuleCmd)
	policiesCmd.AddCommand(getPolicyCmd)
	policiesCmd.AddCommand(createMsftIdPforAppPolicyCmd)

	generateMarkdownDocs(policiesCmd, "./docs/policies/")
}
