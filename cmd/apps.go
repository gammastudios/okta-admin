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
// okta-admin apps list
//
var listAppsCmd = &cobra.Command{
	Use:   "list",
	Short: "Enumerates apps added to your organization.",
	Long:  `Enumerates apps added to your organization. A subset of apps can be returned that match a supported filter expression or query.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Printf("Listing apps in %s", viper.GetString("org"))
		queryParams := retQueryParams(filter)
		// Get data
		ctx, client := getOrCreateClient()
		apps, _, err := client.Application.ListApplications(ctx, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			retResults(apps, jsonquery, format)
		}
	},
}

//
// okta-admin apps deactivate <appId>
//
var deactivateAppCmd = &cobra.Command{
	Use:   "deactivate <appId>",
	Short: "Deactivates an active application.",
	Long:  `Deactivates an active application.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		log.Printf("Deactivating application %s in %s", appId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		resp, err := client.Application.DeactivateApplication(ctx, appId)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
		}
	},
}

//
// okta-admin apps delete <appId>
//
var deleteAppCmd = &cobra.Command{
	Use:   "delete <appId>",
	Short: "Removes an inactive application.",
	Long:  `Removes an inactive application.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		log.Printf("Deleting application %s in %s", appId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		resp, err := client.Application.DeleteApplication(ctx, appId)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
		}
	},
}

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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// usersCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// usersCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	//listAppsCmd.Flags().StringVarP(&filter, "filter", "f", "", "filter expression to filter results (e.g. 'status eq \\\"ACTIVE\\\"')")
	//listAppsCmd.Flags().StringVarP(&jsonquery, "jsonquery", "q", "", "Json query to extract specified fields from a response object ()")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// appsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// appsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	generateMarkdownDocs(appsCmd, "./docs/apps/")

}
