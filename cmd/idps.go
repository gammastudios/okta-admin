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
		idps, _, err := client.IdentityProvider.ListIdentityProviders(ctx, queryParams)
		if err != nil {
			panic(err)
		}
		b, err := json.Marshal(idps)
		if err != nil {
			panic(err)
		} else {
			retResults(b, jsonquery)
		}
	},
}

/*
ActivateIdentityProvider
CloneIdentityProviderKey
CreateIdentityProvider
CreateIdentityProviderKey
DeactivateIdentityProvider
DeleteIdentityProvider
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
ListIdentityProviderApplicationUsers
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
UnlinkUserFromIdentityProvider
UpdateIdentityProvider
*/

func init() {
	rootCmd.AddCommand(idpsCmd)
	idpsCmd.AddCommand(listIdpsCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// usersCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// usersCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	listIdpsCmd.Flags().StringVarP(&filter, "filter", "f", "", "filter expression to filter results (e.g. 'status eq \\\"ACTIVE\\\"')")
	listIdpsCmd.Flags().StringVarP(&jsonquery, "jsonquery", "q", "", "Json query to extract specified fields from a response object ()")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// appsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// appsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	generateMarkdownDocs(idpsCmd, "./docs/idps/")
}
