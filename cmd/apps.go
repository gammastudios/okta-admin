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
// Output Operations (return data)
//

// okta-admin apps list
var listAppsCmd = &cobra.Command{
	Use:   "list",
	Short: "Enumerates apps added to your organization.",
	Long:  `Enumerates apps added to your organization. A subset of apps can be returned that match a supported filter expression or query.`,
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		queryParams := retQueryParams(filter)
		log.Printf("Listing apps in %s", viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Application.ListApplications(ctx, queryParams))
	},
}

// okta-admin listgroupassignments <appId>
var listAppGroupAssignmentsCmd = &cobra.Command{
	Use:   "listgroupassignments <appId>",
	Short: "Enumerates group assignments for an application.",
	Long:  `Enumerates group assignments for an application.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Listing group assignments for app %s in %s", appId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Application.ListApplicationGroupAssignments(ctx, appId, queryParams))
	},
}

// okta-admin listkeys <appId>
var listAppKeysCmd = &cobra.Command{
	Use:   "listkeys <appId>",
	Short: "Enumerates key credentials for an application.",
	Long:  `Enumerates key credentials for an application.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		log.Printf("Listing keys for app %s in %s", appId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Application.ListApplicationKeys(ctx, appId))
	},
}

// okta-admin listusers <appId>
var listAppUsersCmd = &cobra.Command{
	Use:   "listusers <appId>",
	Short: "Enumerates all assigned [application users](#application-user-model) for an application.",
	Long:  `Enumerates all assigned [application users](#application-user-model) for an application.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Listing users for app %s in %s", appId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Application.ListApplicationUsers(ctx, appId, queryParams))
	},
}

// okta-admin listcsrs <appId>
var listAppCsrsCmd = &cobra.Command{
	Use:   "listcsrs <appId>",
	Short: "Enumerates Certificate Signing Requests for an application.",
	Long:  `Enumerates Certificate Signing Requests for an application.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		log.Printf("Listing csrs for app %s in %s", appId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Application.ListCsrsForApplication(ctx, appId))
	},
}

// okta-admin listtokens <appId>
var listAppTokensCmd = &cobra.Command{
	Use:   "listtokens <appId>",
	Short: "Lists all tokens for the application.",
	Long:  `Lists all tokens for the application.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Listing tokens for app %s in %s", appId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Application.ListOAuth2TokensForApplication(ctx, appId, queryParams))
	},
}

// okta-admin listscopeconsentgrants <appId>
var listAppScopeConsentGrantsCmd = &cobra.Command{
	Use:   "listscopeconsentgrants <appId>",
	Short: "Lists all scope consent grants for the application.",
	Long:  `Lists all scope consent grants for the application.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Listing scope consent grants for app %s in %s", appId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Application.ListScopeConsentGrants(ctx, appId, queryParams))
	},
}

// okta-admin apps get <appId>
var getAppCmd = &cobra.Command{
	Use:   "get <appId>",
	Short: "Fetches an application from your Okta organization by ID.",
	Long:  `Fetches an application from your Okta organization by ID.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		//var appInstance okta.App
		appId := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Getting app %s, in %s", appId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Application.GetApplication(ctx, appId, okta.NewApplication(), queryParams))
	},
}

// GetApplicationGroupAssignment
// GetApplicationKey
// GetApplicationUser
// GetCsrForApplication
// GetOAuth2TokenForApplication
// GetScopeConsentGrant

// AssignUserToApplication
// Assigns an user to an application with [credentials](#application-user-credentials-object) and an app-specific [profile](#application-user-profile-object). Profile mappings defined for the application are first applied before applying any profile properties specified in the request.
// func (m *ApplicationResource) AssignUserToApplication(ctx context.Context, appId string, body AppUser) (*AppUser, *Response, error) {
//	url := fmt.Sprintf("/api/v1/apps/%v/users", appId)

//CloneApplicationKey
// Clones a X.509 certificate for an application key credential from a source application to target application.
// func (m *ApplicationResource) CloneApplicationKey(ctx context.Context, appId string, keyId string, qp *query.Params) (*JsonWebKey, *Response, error) {
//	url := fmt.Sprintf("/api/v1/apps/%v/credentials/keys/%v/clone", appId, keyId)

// GrantConsentToScope
// Grants consent for the application to request an OAuth 2.0 Okta scope
// func (m *ApplicationResource) GrantConsentToScope(ctx context.Context, appId string, body OAuth2ScopeConsentGrant) (*OAuth2ScopeConsentGrant, *Response, error) {
//	url := fmt.Sprintf("/api/v1/apps/%v/grants", appId)

// GenerateApplicationKey
// GenerateCsrForApplication

// PublishBinaryCerCert
// func (m *ApplicationResource) PublishBinaryCerCert(ctx context.Context, appId string, csrId string, body string) (*JsonWebKey, *Response, error) {
// 	url := fmt.Sprintf("/api/v1/apps/%v/credentials/csrs/%v/lifecycle/publish", appId, csrId)

// PublishBinaryDerCert
// func (m *ApplicationResource) PublishBinaryDerCert(ctx context.Context, appId string, csrId string, body string) (*JsonWebKey, *Response, error) {
// 	url := fmt.Sprintf("/api/v1/apps/%v/credentials/csrs/%v/lifecycle/publish", appId, csrId)

// PublishBinaryPemCert
// func (m *ApplicationResource) PublishBinaryPemCert(ctx context.Context, appId string, csrId string, body string) (*JsonWebKey, *Response, error) {
// 	url := fmt.Sprintf("/api/v1/apps/%v/credentials/csrs/%v/lifecycle/publish", appId, csrId)

// PublishCerCert
// func (m *ApplicationResource) PublishCerCert(ctx context.Context, appId string, csrId string, body string) (*JsonWebKey, *Response, error) {
// 	url := fmt.Sprintf("/api/v1/apps/%v/credentials/csrs/%v/lifecycle/publish", appId, csrId)

// PublishDerCert
// func (m *ApplicationResource) PublishDerCert(ctx context.Context, appId string, csrId string, body string) (*JsonWebKey, *Response, error) {
// 	url := fmt.Sprintf("/api/v1/apps/%v/credentials/csrs/%v/lifecycle/publish", appId, csrId)

//
// okta-admin apps create <jsonBody>
var createApplicationCmd = &cobra.Command{
	Use:   "create <jsonBody>",
	Short: "Adds a new application to your Okta organization.",
	Long:  `Adds a new application to your Okta organization.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		jsonBody := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Creating new application in %s", viper.GetString("org"))
		ctx, client := getOrCreateClient()
		var body okta.App
		json.Unmarshal([]byte(jsonBody), &body)
		processOutput(client.Application.CreateApplication(ctx, body, queryParams))
	},
}

// okta-admin apps createoidcapp <appName> <loginRedirectUrl>
var createOidcApplicationCmd = &cobra.Command{
	Use:   "createoidcapp <appName> <appType web|native|browser|spa|service> <loginRedirectUrl>",
	Short: "Adds a new OIDC application to your Okta organization.",
	Long:  `Adds a new OIDC application to your Okta organization.`,
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		appName := args[0]
		appType := args[1]
		loginRedirectUrl := args[2]
		queryParams := retQueryParams(filter)

		const (
			authorizationCode string = "authorization_code"
			implicit          string = "implicit"
			password          string = "password"
			refreshToken      string = "refresh_token"
			clientCredentials string = "client_credentials"
			code              string = "code"
			token             string = "token"
			id_token          string = "id_token"
		)

		var grantTypes []string
		var responseTypes []string

		switch appType {
		case "web":
			grantTypes = []string{authorizationCode}
			responseTypes = []string{code}
		case "native":
			grantTypes = []string{authorizationCode}
			responseTypes = []string{code}
		case "browser", "spa":
			appType = "browser"
			grantTypes = []string{authorizationCode, implicit, refreshToken}
			responseTypes = []string{code, token, id_token}
		case "service":
			grantTypes = []string{clientCredentials}
			responseTypes = []string{token}
		default:
			log.Println("appType argument must be 'web', 'native', 'browser', 'spa' or 'service' only")
		}

		oktaGrantTypes := make([]*okta.OAuthGrantType, len(grantTypes))
		for i := range grantTypes {
			gt := okta.OAuthGrantType(grantTypes[i])
			oktaGrantTypes[i] = &gt
		}

		oktaResponseTypes := make([]*okta.OAuthResponseType, len(responseTypes))
		for i := range responseTypes {
			gt := okta.OAuthResponseType(responseTypes[i])
			oktaResponseTypes[i] = &gt
		}

		oktaRedirectUris := []string{loginRedirectUrl}

		appSettingsClient := okta.NewOpenIdConnectApplicationSettingsClient()
		appSettingsClient.ApplicationType = appType
		//appSettingsClient.ClientUri = "https://example.com/client"
		//appSettingsClient.LogoUri = "https://example.com/assets/images/logo-new.png"
		//appSettingsClient.PolicyUri = "https://example.com/client/policy"
		//appSettingsClient.TosUri = "https://example.com/client/tos"
		appSettingsClient.GrantTypes = oktaGrantTypes
		appSettingsClient.RedirectUris = oktaRedirectUris
		appSettingsClient.ResponseTypes = oktaResponseTypes
		appSettingsClient.ConsentMethod = "REQUIRED"

		appSettings := okta.NewOpenIdConnectApplicationSettings()
		appSettings.OauthClient = appSettingsClient

		/*
			app.Credentials = &okta.OAuthApplicationCredentials{
				OauthClient: &okta.ApplicationCredentialsOAuthClient{
					AutoKeyRotation:         boolPtr(d.Get("auto_key_rotation").(bool)),
					ClientId:                d.Get("client_id").(string),
					TokenEndpointAuthMethod: authMethod,
				},
			}
		*/

		appCredentials := okta.NewOAuthApplicationCredentials()
		oauthClient := okta.NewApplicationCredentialsOAuthClient()
		oauthClient.TokenEndpointAuthMethod = "none"
		appCredentials.OauthClient = oauthClient

		app := okta.NewOpenIdConnectApplication()
		app.Label = appName
		app.Settings = appSettings
		app.Credentials = appCredentials

		//var jsonData []byte
		//jsonData, err := json.Marshal(app)
		//if err != nil {
		//	log.Println(err)
		//}
		//log.Println(string(jsonData))

		log.Printf("Creating new OIDC application in %s", viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Application.CreateApplication(ctx, app, queryParams))
	},
}

// UpdateApplication
// CreateApplicationGroupAssignment
// UpdateApplicationUser

//
// State Only Operations (return resp code)
//

// okta-admin apps activate <appId>
var activateAppCmd = &cobra.Command{
	Use:   "activate <appId>",
	Short: "Activates an inactive application.",
	Long:  `Activates an inactive application.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		log.Printf("Activating application %s in %s", appId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.Application.ActivateApplication(ctx, appId)
		processOutput(nil, resp, err)
	},
}

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

// okta-admin apps deletegroupassignment <appId> <groupId>
var deleteAppGroupAssignmentCmd = &cobra.Command{
	Use:   "deletegroupassignment <appId> <groupId>",
	Short: "Removes a group assignment from an application.",
	Long:  `Removes a group assignment from an application.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		groupId := args[1]
		log.Printf("Removing group assignment %s for application %s in %s", groupId, appId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.Application.DeleteApplicationGroupAssignment(ctx, appId, groupId)
		processOutput(nil, resp, err)
	},
}

// okta-admin apps deleteuser <appId> <userId>
var deleteAppUserCmd = &cobra.Command{
	Use:   "deleteuser <appId> <userId>",
	Short: "Removes an assignment for a user from an application.",
	Long:  `Removes an assignment for a user from an application.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		userId := args[1]
		queryParams := retQueryParams(filter)
		log.Printf("Removing user assignment %s for application %s in %s", userId, appId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.Application.DeleteApplicationUser(ctx, appId, userId, queryParams)
		processOutput(nil, resp, err)
	},
}

// okta-admin apps revokecsr <appId> <csrId>
var revokeCsrFromAppCmd = &cobra.Command{
	Use:   "revokecsr <appId> <csrId>",
	Short: "Revokes a CSR for an application.",
	Long:  `Revokes a CSR for an application.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		csrId := args[1]
		log.Printf("Revoking CSR %s for application %s in %s", csrId, appId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.Application.RevokeCsrFromApplication(ctx, appId, csrId)
		processOutput(nil, resp, err)
	},
}

// okta-admin apps revoketoken <appId> [<tokenId>]
var revokeTokenFromAppCmd = &cobra.Command{
	Use:   "revoketoken <appId> [<tokenId>]",
	Short: "Revokes the specified token for the specified application (or all tokens if none are specified).",
	Long:  `Revokes the specified token for the specified application (or all tokens if none are specified).`,
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		var resp *okta.Response
		var err error
		appId := args[0]
		ctx, client := getOrCreateClient()
		if len(args) == 2 {
			tokenId := args[1]
			log.Printf("Revoking token %s for application %s in %s", tokenId, appId, viper.GetString("org"))
			resp, err = client.Application.RevokeOAuth2TokenForApplication(ctx, appId, tokenId)
		} else {
			log.Printf("Revoking all tokens for application %s in %s", appId, viper.GetString("org"))
			resp, err = client.Application.RevokeOAuth2TokensForApplication(ctx, appId)
		}
		processOutput(nil, resp, err)
	},
}

// okta-admin apps revokescopeconsentgrant <appId> <grantId>
var revokeScopeConsentGrantCmd = &cobra.Command{
	Use:   "revokescopeconsentgrant <appId> <grantId>",
	Short: "Revokes permission for the application to request the given scope.",
	Long:  `Revokes permission for the application to request the given scope.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		appId := args[0]
		grantId := args[1]
		log.Printf("Revoking scope consent grant %s for application %s in %s", grantId, appId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.Application.RevokeScopeConsentGrant(ctx, appId, grantId)
		processOutput(nil, resp, err)
	},
}

func init() {
	rootCmd.AddCommand(appsCmd)
	appsCmd.AddCommand(listAppsCmd)
	appsCmd.AddCommand(deactivateAppCmd)
	appsCmd.AddCommand(deleteAppCmd)
	appsCmd.AddCommand(listAppGroupAssignmentsCmd)
	appsCmd.AddCommand(listAppKeysCmd)
	appsCmd.AddCommand(deleteAppGroupAssignmentCmd)
	appsCmd.AddCommand(deleteAppUserCmd)
	appsCmd.AddCommand(revokeCsrFromAppCmd)
	appsCmd.AddCommand(revokeTokenFromAppCmd)
	appsCmd.AddCommand(revokeScopeConsentGrantCmd)
	appsCmd.AddCommand(listAppUsersCmd)
	appsCmd.AddCommand(listAppCsrsCmd)
	appsCmd.AddCommand(listAppTokensCmd)
	appsCmd.AddCommand(listAppScopeConsentGrantsCmd)
	appsCmd.AddCommand(getAppCmd)
	appsCmd.AddCommand(createOidcApplicationCmd)

	generateMarkdownDocs(appsCmd, "./docs/apps/")

}
