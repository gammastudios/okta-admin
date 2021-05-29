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
// Query Operations (return data)
//

// okta-admin idps list
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

// okta-admin idps listusers <idpId>
var listUsersForIdpCmd = &cobra.Command{
	Use:   "listusers <idpId>",
	Short: "Find all the users linked to an identity provider.",
	Long:  `Find all the users linked to an identity provider.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		log.Printf("Listing users linked to idp %s in %s", idpId, viper.GetString("org"))
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

// okta-admin idps listcsrs <idpId>
var listCsrsForIdpCmd = &cobra.Command{
	Use:   "listcsrs <idpId>",
	Short: "Enumerates Certificate Signing Requests for an IdP.",
	Long:  `Enumerates Certificate Signing Requests for an IdP.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		log.Printf("Listing csrs for idp %s in %s", idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.IdentityProvider.ListCsrsForIdentityProvider(ctx, idpId)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

// okta-admin idps listkeys [<idpId>]
var listIdpKeysCmd = &cobra.Command{
	// overloaded command
	Use:   "listkeys [<idpId>]",
	Short: "Enumerates keys or signing key credentials for an IdP if specified.",
	Long:  `Enumerates keys or signing key credentials for an IdP if specified.`,
	Args:  cobra.RangeArgs(0, 1),
	Run: func(cmd *cobra.Command, args []string) {
		var idpId string
		var data interface{}
		var err error
		queryParams := retQueryParams(filter)
		ctx, client := getOrCreateClient()
		if len(args) == 1 {
			idpId = args[0]
			log.Printf("Listing signing key credentials for IdP %s in %s", idpId, viper.GetString("org"))
			// Get data
			data, _, err = client.IdentityProvider.ListIdentityProviderSigningKeys(ctx, idpId)
		} else {
			log.Printf("Listing idp keys in %s", viper.GetString("org"))
			// Get data
			data, _, err = client.IdentityProvider.ListIdentityProviderKeys(ctx, queryParams)
		}
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

// okta-admin idps listsocialauthtokens <idpId> <userId>
var listSocialAuthTokensCmd = &cobra.Command{
	Use:   "listsocialauthtokens <idpId> <userId>",
	Short: "Fetches the tokens minted by the Social Authentication Provider when the user authenticates with Okta via Social Auth.",
	Long:  `Fetches the tokens minted by the Social Authentication Provider when the user authenticates with Okta via Social Auth.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		userId := args[1]
		log.Printf("Fetching social auth tokens for idp %s, user %s, in %s", idpId, userId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.IdentityProvider.ListSocialAuthTokens(ctx, idpId, userId)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

// okta-admin idps get <idpId>
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

// okta-admin idps getcsr <idpId> <csrId>
var getCsrCmd = &cobra.Command{
	Use:   "getcsr <idpId> <csrId>",
	Short: "Gets a specific Certificate Signing Request model by id.",
	Long:  `Gets a specific Certificate Signing Request model by id.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		csrId := args[1]
		log.Printf("Fetching csr %s for idp %s in %s", csrId, idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.IdentityProvider.GetCsrForIdentityProvider(ctx, idpId, csrId)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

// okta-admin idps getuser <idpId> <userId>
var getIdpUserCmd = &cobra.Command{
	Use:   "getuser <idpId> <userId>",
	Short: "Fetches a linked IdP user by ID.",
	Long:  `Fetches a linked IdP user by ID.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		userId := args[1]
		log.Printf("Fetching user %s for idp %s in %s", userId, idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.IdentityProvider.GetIdentityProviderApplicationUser(ctx, idpId, userId)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

// okta-admin idps getkey <keyId>
var getIdpKeyCmd = &cobra.Command{
	Use:   "getkey <keyId>",
	Short: "Gets a specific IdP Key Credential by KEYID.",
	Long:  `Gets a specific IdP Key Credential by KEYID.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyId := args[0]
		log.Printf("Fetching key %s in %s", keyId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.IdentityProvider.GetIdentityProviderKey(ctx, keyId)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

// okta-admin idps getkeybyidp <idpId> <keyId>
var getIdpSigningKeyCmd = &cobra.Command{
	Use:   "getkeybyidp <idpId> <keyId>",
	Short: "Gets a specific IdP Key Credential by KEYID",
	Long:  `Gets a specific IdP Key Credential by KEYID`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		keyId := args[1]
		log.Printf("Fetching key %s for idp %s in %s", keyId, idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.IdentityProvider.GetIdentityProviderSigningKey(ctx, idpId, keyId)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// Data Generating Operations (returns data)
//

// okta-admin idps generatecsr <idpId> <jsonBody>
var generateCsrCmd = &cobra.Command{
	Use:   "generatecsr <idpId> <jsonBody>",
	Short: "Generates a new key pair and returns a Certificate Signing Request for it.",
	Long:  `Generates a new key pair and returns a Certificate Signing Request for it.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		jsonBody := args[1]
		log.Printf("Generating CSR for idp %s in %s", idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		var body *okta.CsrMetadata
		body = new(okta.CsrMetadata)
		json.Unmarshal([]byte(jsonBody), &body)
		data, resp, err := client.IdentityProvider.GenerateCsrForIdentityProvider(ctx, idpId, *body)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
			retResults(data, jsonquery, format)
		}
	},
}

// okta-admin idps generatekey <idpId>
var generateKeyCmd = &cobra.Command{
	Use:   "generatekey <idpId>",
	Short: "Generates a new X.509 certificate for an IdP signing key credential to be used for signing assertions sent to the IdP.",
	Long:  `Generates a new X.509 certificate for an IdP signing key credential to be used for signing assertions sent to the IdP.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		queryParams := retQueryParams(filter)
		idpId := args[0]
		log.Printf("Generating key for idp %s in %s", idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, resp, err := client.IdentityProvider.GenerateIdentityProviderSigningKey(ctx, idpId, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
			retResults(data, jsonquery, format)
		}
	},
}

//
// Action Operations (return resp code)
//

// okta-admin idps deactivate <idpId>
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

// okta-admin idps delete <idpId>
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

// okta-admin idps activate <idpId>
var activateIdpCmd = &cobra.Command{
	Use:   "activate <idpId>",
	Short: "Activates  an active IdP.",
	Long:  `Activates  an active IdP.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		log.Printf("Activating idp %s in %s", idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		_, resp, err := client.IdentityProvider.ActivateIdentityProvider(ctx, idpId)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
		}
	},
}

// okta-admin idps clonekey <idpId> <keyId>
var cloneIdpKeyCmd = &cobra.Command{
	Use:   "clonekey <idpId> <keyId>",
	Short: "Clones a X.509 certificate for an IdP signing key credential from a source IdP to target IdP.",
	Long:  `Clones a X.509 certificate for an IdP signing key credential from a source IdP to target IdP.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		keyId := args[1]
		queryParams := retQueryParams(filter)
		log.Printf("Cloning key %s for idp %s in %s", keyId, idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		_, resp, err := client.IdentityProvider.CloneIdentityProviderKey(ctx, idpId, keyId, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
		}
	},
}

// okta-admin idps deletekey <keyId>
var deleteIdpKeyCmd = &cobra.Command{
	Use:   "deletekey <keyId>",
	Short: "Deletes a specific IdP Key Credential by KEYID if it is not currently being used by an Active or Inactive IdP.",
	Long:  `Deletes a specific IdP Key Credential by KEYID if it is not currently being used by an Active or Inactive IdP.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyId := args[0]
		log.Printf("Deleting key %s in %s", keyId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		resp, err := client.IdentityProvider.DeleteIdentityProviderKey(ctx, keyId)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
		}
	},
}

// okta-admin idps linkuser <idpId> <userId> <jsonBody>
var linkUserToIdpCmd = &cobra.Command{
	Use:   "linkuser <idpId> <userId> <jsonBody>",
	Short: "Links an Okta user to an existing Social Identity Provider.",
	Long:  `Links an Okta user to an existing Social Identity Provider. This does not support the SAML2 Identity Provider Type.`,
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		userId := args[1]
		jsonBody := args[2]
		log.Printf("Linking user %s to idp %s in %s", userId, idpId, viper.GetString("org"))
		var body okta.UserIdentityProviderLinkRequest
		json.Unmarshal([]byte(jsonBody), &body)
		// Get data
		ctx, client := getOrCreateClient()
		_, resp, err := client.IdentityProvider.LinkUserToIdentityProvider(ctx, idpId, userId, body)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
		}
	},
}

// okta-admin idps unlinkuser <idpId> <userId>
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

// okta-admin idps publishcer <idpId> <csrId> <certtype: cer|der|pem>
var publishBinaryCertForIdpCmd = &cobra.Command{
	Use:   "publishcert <idpId> <csrId> <body> <type: cer|der|pem>",
	Short: "Update the Certificate Signing Request with a signed X.509 certificate and add it into the signing key credentials for the IdP.",
	Long:  `Update the Certificate Signing Request with a signed X.509 certificate and add it into the signing key credentials for the IdP.`,
	Args:  cobra.ExactArgs(4),
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		var resp *okta.Response
		idpId := args[0]
		csrId := args[1]
		body := args[2]
		certtype := args[3]
		if certtype == "cer" || certtype == "der" || certtype == "pem" {
			log.Printf("Publishing cert (%s) csr %s for idp %s in %s", certtype, csrId, idpId, viper.GetString("org"))
			// Get data
			ctx, client := getOrCreateClient()
			switch certtype {
			case "cer":
				_, resp, err = client.IdentityProvider.PublishBinaryCerCertForIdentityProvider(ctx, idpId, csrId, body)
				/* has same signature as PublishCerCertForIdentityProvider */
			case "der":
				_, resp, err = client.IdentityProvider.PublishBinaryDerCertForIdentityProvider(ctx, idpId, csrId, body)
				/* has same signature as PublishDerCertForIdentityProvider */
			case "pem":
				_, resp, err = client.IdentityProvider.PublishBinaryPemCertForIdentityProvider(ctx, idpId, csrId, body)
			}
			if err != nil {
				log.Println(err)
			} else {
				log.Println(resp.Status)
			}
		} else {
			log.Println("certtype argument must be 'cer', 'der' or 'pem' only")
		}
	},
}

// okta-admin idps revokecsr <idpId> <csrId>
var revokeCsrCmd = &cobra.Command{
	Use:   "revokecsr <idpId> <csrId>",
	Short: "Revoke a Certificate Signing Request and delete the key pair from the IdP.",
	Long:  `Revoke a Certificate Signing Request and delete the key pair from the IdP.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		csrId := args[1]
		log.Printf("Revoking csr %s from idp %s in %s", csrId, idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		resp, err := client.IdentityProvider.RevokeCsrForIdentityProvider(ctx, idpId, csrId)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
		}
	},
}

//
// Mutation Operations (return resp code)
//

// okta-admin idps create <jsonBody>
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

// okta-admin idps createmsft <name> <clientId> <clientSecret>
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

// okta-admin idps createkey <jsonBody>
var createIdpKeyCmd = &cobra.Command{
	Use:   "createkey <jsonBody>",
	Short: "Adds a new X.509 certificate credential to the IdP key store.",
	Long:  `Adds a new X.509 certificate credential to the IdP key store.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		jsonBody := args[0]
		log.Printf("Creating new X.509 certificate credential in %s", viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		var body *okta.JsonWebKey
		body = new(okta.JsonWebKey)
		json.Unmarshal([]byte(jsonBody), &body)
		_, resp, err := client.IdentityProvider.CreateIdentityProviderKey(ctx, *body)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
		}
	},
}

// okta-admin idps update <idpId> <jsonBody>
var updateIdpCmd = &cobra.Command{
	Use:   "update <idpId> <jsonBody>",
	Short: "Updates the configuration for an IdP.",
	Long:  `Updates the configuration for an IdP.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		idpId := args[0]
		jsonBody := args[1]
		log.Printf("Updating configuration for idp %s in %s", idpId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		var body okta.IdentityProvider
		json.Unmarshal([]byte(jsonBody), &body)
		_, resp, err := client.IdentityProvider.UpdateIdentityProvider(ctx, idpId, body)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(resp.Status)
		}
	},
}

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
	idpsCmd.AddCommand(createIdpKeyCmd)
	idpsCmd.AddCommand(activateIdpCmd)
	idpsCmd.AddCommand(cloneIdpKeyCmd)
	idpsCmd.AddCommand(deleteIdpKeyCmd)
	idpsCmd.AddCommand(listCsrsForIdpCmd)
	idpsCmd.AddCommand(listIdpKeysCmd)
	idpsCmd.AddCommand(listSocialAuthTokensCmd)
	idpsCmd.AddCommand(getCsrCmd)
	idpsCmd.AddCommand(getIdpUserCmd)
	idpsCmd.AddCommand(getIdpKeyCmd)
	idpsCmd.AddCommand(getIdpSigningKeyCmd)
	idpsCmd.AddCommand(generateCsrCmd)
	idpsCmd.AddCommand(generateKeyCmd)
	idpsCmd.AddCommand(updateIdpCmd)
	idpsCmd.AddCommand(linkUserToIdpCmd)
	idpsCmd.AddCommand(publishBinaryCertForIdpCmd)
	idpsCmd.AddCommand(revokeCsrCmd)

	//generateMarkdownDocs(idpsCmd, "./docs/idps/")
}
