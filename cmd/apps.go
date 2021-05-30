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
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// appsCmd represents the apps command
var appsCmd = &cobra.Command{
	Use:   "apps",
	Short: "Provides operations to manage applications and/or assignments to users or groups for your organization.",
	Long: `Provides operations to manage applications and/or assignments to users or groups for your organization. For example:

okta-admin apps list
okta-admin apps create
		`,
	Args: cobra.MinimumNArgs(1),
}

//
// Query Operations (return data)
//

// okta-admin apps list
var listAppsCmd = &cobra.Command{
	Use:   "list",
	Short: "Enumerates apps added to your organization.",
	Long:  `Enumerates apps added to your organization. A subset of apps can be returned that match a supported filter expression or query.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Printf("Listing apps in %s", viper.GetString("org"))
		queryParams := retQueryParams(filter)
		ctx, client := getOrCreateClient()
		processOutput(client.Application.ListApplications(ctx, queryParams))
	},
}

//
// Action Operations (return resp code)
//

// okta-admin apps deactivate <appId>
var deactivateAppCmd = &cobra.Command{
	Use:   "deactivate <appId>",
	Short: "Deactivates an active application.",
	Long:  `Deactivates an active application.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		log.Printf("Deactivating application %s in %s", appId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.Application.DeactivateApplication(ctx, appId)
		processOutput(nil, resp, err)
	},
}

// okta-admin apps delete <appId>
var deleteAppCmd = &cobra.Command{
	Use:   "delete <appId>",
	Short: "Removes an inactive application.",
	Long:  `Removes an inactive application.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		log.Printf("Deleting application %s in %s", appId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.Application.DeleteApplication(ctx, appId)
		processOutput(nil, resp, err)
	},
}

//
// Mutation Operations (create or update objects)
//

/*
ActivateApplication
AssignUserToApplication
CloneApplicationKey
CreateApplication
CreateApplicationGroupAssignment
DeleteApplicationGroupAssignment
DeleteApplicationUser
GenerateApplicationKey
GenerateCsrForApplication
GetApplication
GetApplicationGroupAssignment
GetApplicationKey
GetApplicationUser
GetCsrForApplication
GetOAuth2TokenForApplication
GetScopeConsentGrant
GrantConsentToScope
ListApplicationGroupAssignments
ListApplicationKeys
ListApplicationUsers
ListApplications
ListCsrsForApplication
ListOAuth2TokensForApplication
ListScopeConsentGrants
PublishBinaryCerCert
PublishBinaryDerCert
PublishBinaryPemCert
PublishCerCert
PublishDerCert
RevokeCsrFromApplication
RevokeOAuth2TokenForApplication
RevokeOAuth2TokensForApplication
RevokeScopeConsentGrant
UpdateApplication
UpdateApplicationUser
*/

func init() {
	rootCmd.AddCommand(appsCmd)
	appsCmd.AddCommand(listAppsCmd)
	appsCmd.AddCommand(deactivateAppCmd)
	appsCmd.AddCommand(deleteAppCmd)

	generateMarkdownDocs(appsCmd, "./docs/apps/")

}
