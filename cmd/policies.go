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
	"log"

	"github.com/okta/okta-sdk-golang/v2/okta"
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
// Output Operations (return data)
//

// okta-admin policies list
var listPoliciesCmd = &cobra.Command{
	Use:   "list",
	Short: "Lists policies in your organization.",
	Long:  `Lists policies in your organization.`,
	Run: func(cmd *cobra.Command, args []string) {
		queryParams := retQueryParams(filter)
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

/* policy client.Policy
ActivatePolicy
ActivatePolicyRule
CreatePolicy
DeactivatePolicy
DeactivatePolicyRule
DeletePolicy
DeletePolicyRule
GetPolicy
UpdatePolicy
UpdatePolicyRule
*/

func init() {
	rootCmd.AddCommand(policiesCmd)
	policiesCmd.AddCommand(listPoliciesCmd)
	policiesCmd.AddCommand(listPolicyRulesCmd)
	policiesCmd.AddCommand(getPolicyRuleCmd)

	generateMarkdownDocs(policiesCmd, "./docs/policies/")
}
