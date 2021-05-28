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

//
// okta-admin idps get <idpId>
//
var getIdpCmd = &cobra.Command{
	Use:   "get <idpId>",
	Short: "Fetches an IdP by ID.",
	Long:  `Fetches an IdP by ID.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		log.Printf("Fetching idp %s in %s", idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.IdentityProvider.GetIdentityProvider(ctx, idpId)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin idps create <jsonBody>
//
var createIdpCmd = &cobra.Command{
	Use:   "create <jsonBody>",
	Short: "Adds a new IdP to your organization.",
	Long:  `Adds a new IdP to your organization.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		jsonBody := args[0]
		log.Printf("Creating new idp in %s", viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		var body *okta.IdentityProvider
		body = new(okta.IdentityProvider)
		json.Unmarshal([]byte(jsonBody), &body)
		_, resp, err := client.IdentityProvider.CreateIdentityProvider(ctx, *body)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
		}
	},
}

//
// okta-admin idps createmsft <name> <clientId> <clientSecret>
//
var createMsftIdpCmd = &cobra.Command{
	Use:   "createmsft <name> <clientId> <clientSecret>",
	Short: "Adds a new Microsoft SSO IdP to your organization.",
	Long:  `Adds a new Microsoft SSO IdP to your organization.`,
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		clientId := args[1]
		clientSecret := args[2]
		log.Printf("Creating new Microsoft idp %s in %s", name, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		var body *okta.IdentityProvider
		body = new(okta.IdentityProvider)
		data := `
		{
			"protocol": {
			 "credentials": {
			  "client": {
			   "client_id": "",
			   "client_secret": ""
			  }
			 },
			 "scopes": [
			  "https://graph.microsoft.com/User.Read",
			  "email",
			  "openid",
			  "profile"
			 ],
			 "type": "OIDC"
			},
			"status": "ACTIVE",
			"type": "MICROSOFT",
			"name": "",
			"policy": {
				"accountLink": {
				 "action": "AUTO"
				},
				"provisioning": {
				 "action": "DISABLED",
				 "conditions": {
				  "deprovisioned": {
				   "action": "NONE"
				  },
				  "suspended": {
				   "action": "NONE"
				  }
				 },
				 "groups": {
				  "action": "NONE"
				 },
				 "profileMaster": false
				},
				"subject": {
				 "matchType": "USERNAME",
				 "userNameTemplate": {
				  "template": "idpuser.userPrincipalName"
				 }
				}
			   }
		   }
		`
		json.Unmarshal([]byte(data), &body)
		body.Name = name
		body.Protocol.Credentials.Client.ClientId = clientId
		body.Protocol.Credentials.Client.ClientSecret = clientSecret
		_, resp, err := client.IdentityProvider.CreateIdentityProvider(ctx, *body)
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
CreateIdentityProviderKey
DeleteIdentityProviderKey
GenerateCsrForIdentityProvider
GenerateIdentityProviderSigningKey
GetCsrForIdentityProvider

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
	idpsCmd.AddCommand(getIdpCmd)
	idpsCmd.AddCommand(createIdpCmd)
	idpsCmd.AddCommand(createMsftIdpCmd)

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
