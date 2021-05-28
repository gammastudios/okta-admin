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

// idpsCmd represents the idps command
var idpsCmd = &cobra.Command{
	Use:   "idps",
	Short: "Provides operations to manage federations with external Identity Providers (IdP).",
	Long: `Provides operations to manage federations with external Identity Providers (IdP). For example, your app can support signing in with credentials from Apple, Facebook, Google, LinkedIn, Microsoft, an enterprise IdP using SAML 2.0, or an IdP using the OpenID Connect (OIDC) protocol. Examples include:

okta-admin idps list
		`,
	Args: cobra.MinimumNArgs(1),
}

//
// okta-admin idps list
//
var listIdpsCmd = &cobra.Command{
	Use:   "list",
	Short: "Enumerates IdPs in your organization with pagination.",
	Long:  `Enumerates IdPs in your organization with pagination. A subset of IdPs can be returned that match a supported filter expression or query.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Printf("Listing idps in %s", viper.GetString("org"))
		queryParams := retQueryParams(filter)
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.IdentityProvider.ListIdentityProviders(ctx, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin idps listusers <idpId>
//
var listUsersForIdpCmd = &cobra.Command{
	Use:   "listusers <idpId>",
	Short: "Find all the users linked to an identity provider.",
	Long:  `Find all the users linked to an identity provider.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		log.Printf("Listing users linked to idps %s in %s", idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.IdentityProvider.ListIdentityProviderApplicationUsers(ctx, idpId)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin idps unlinkuser <idpId> <userId>
//
var unlinkUserFromIdpCmd = &cobra.Command{
	Use:   "unlinkuser <idpId> <userId>",
	Short: "Removes the link between the Okta user and the IdP user.",
	Long:  `Removes the link between the Okta user and the IdP user.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		userId := args[1]
		log.Printf("Unlinking user %s from idp %s in %s", userId, idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		resp, err := client.IdentityProvider.UnlinkUserFromIdentityProvider(ctx, idpId, userId)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
		}
	},
}

//
// okta-admin idps deactivate <idpId>
//
var deactivateIdpCmd = &cobra.Command{
	Use:   "deactivate <idpId>",
	Short: "Deactivates an active IdP.",
	Long:  `Deactivates an active IdP.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		log.Printf("Deactivating idp %s in %s", idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		_, resp, err := client.IdentityProvider.DeactivateIdentityProvider(ctx, idpId)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
		}
	},
}

//
// okta-admin idps delete <idpId>
//
var deleteIdpCmd = &cobra.Command{
	Use:   "delete <idpId>",
	Short: "Removes an IdP from your organization.",
	Long:  `Removes an IdP from your organization.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		log.Printf("Deleting idp %s in %s", idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		resp, err := client.IdentityProvider.DeleteIdentityProvider(ctx, idpId)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
		}
	},
}

/*
ActivateIdentityProvider
CloneIdentityProviderKey
CreateIdentityProvider
CreateIdentityProviderKey
DeleteIdentityProviderKey
GenerateCsrForIdentityProvider
GenerateIdentityProviderSigningKey
GetCsrForIdentityProvider
GetIdentityProvider
GetIdentityProviderApplicationUser
GetIdentityProviderKey
GetIdentityProviderSigningKey
LinkUserToIdentityProvider
ListCsrsForIdentityProvider
ListIdentityProviderKeys
ListIdentityProviderSigningKeys
ListIdentityProviders
ListSocialAuthTokens
PublishBinaryCerCertForIdentityProvider
PublishBinaryDerCertForIdentityProvider
PublishBinaryPemCertForIdentityProvider
PublishCerCertForIdentityProvider
PublishDerCertForIdentityProvider
RevokeCsrForIdentityProvider
UpdateIdentityProvider
*/

func init() {
	rootCmd.AddCommand(idpsCmd)
	idpsCmd.AddCommand(listIdpsCmd)
	idpsCmd.AddCommand(listUsersForIdpCmd)
	idpsCmd.AddCommand(unlinkUserFromIdpCmd)
	idpsCmd.AddCommand(deactivateIdpCmd)
	idpsCmd.AddCommand(deleteIdpCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// usersCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// usersCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	//listIdpsCmd.Flags().StringVarP(&filter, "filter", "f", "", "filter expression to filter results (e.g. 'status eq \\\"ACTIVE\\\"')")
	//listIdpsCmd.Flags().StringVarP(&jsonquery, "jsonquery", "q", "", "Json query to extract specified fields from a response object ()")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// appsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// appsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	generateMarkdownDocs(idpsCmd, "./docs/idps/")
}
