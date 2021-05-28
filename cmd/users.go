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

// usersCmd represents the users command
var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "The Okta User API provides operations to manage users in your organization.",
	Long: `
The Okta User API provides operations to manage users in your organization. For example:

okta-admin users list
okta-admin users create
	`,
	Args: cobra.MinimumNArgs(1),
}

//
// okta-admin users list
//
var listUsersCmd = &cobra.Command{
	Use:   "list",
	Short: "Lists users in your organization.",
	Long:  `Lists users in your organization.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Printf("Listing users in %s", viper.GetString("org"))
		queryParams := retQueryParams(filter)
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.User.ListUsers(ctx, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin users get <userId>
//
var getUserCmd = &cobra.Command{
	Use:   "get <userId>",
	Short: "Fetches a user from your Okta organization.",
	Long:  `Fetches a user from your Okta organization.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Fetching user %s in %s", userId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.User.GetUser(ctx, userId)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin users listapplinks <userId>
//
var listAppLinksCmd = &cobra.Command{
	Use:   "listapplinks <userId>",
	Short: "Fetches appLinks for all direct or indirect (via group membership) assigned applications.",
	Long:  `Fetches appLinks for all direct or indirect (via group membership) assigned applications.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Fetching appLinks for user %s in %s", userId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.User.ListAppLinks(ctx, userId)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin users listapptargets <userId> <roleId>
//
var listAppTgtsCmd = &cobra.Command{
	Use:   "listapptargets <userId> <roleId>",
	Short: "Lists all App targets for an APP_ADMIN Role assigned to a User.",
	Long: `Lists all App targets for an APP_ADMIN Role assigned to a User. 
This methods return list may include full Applications or Instances. 
The response for an instance will have an ID value, while Application will not have an ID.`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		roleId := args[1]
		log.Printf("Listing App targets for user %s, role %s, in %s", userId, roleId, viper.GetString("org"))
		queryParams := retQueryParams(filter)
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.User.ListApplicationTargetsForApplicationAdministratorRoleForUser(ctx, userId, roleId, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin users listroles <userId>
//
var listRolesCmd = &cobra.Command{
	Use:   "listroles <userId>",
	Short: "Lists all roles assigned to a user.",
	Long:  `Lists all roles assigned to a user.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Listing roles for user %s in %s", userId, viper.GetString("org"))
		queryParams := retQueryParams(filter)
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.User.ListAssignedRolesForUser(ctx, userId, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin users listgrants <userId> [<clientId>]
//
var listGrantsCmd = &cobra.Command{
	// overloaded command
	Use:   "listgrants <userId> [<clientId>]",
	Short: "Lists all grants for a specified user and client if specified.",
	Long:  `Lists all grants for a specified user and client if specified.`,
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		var clientId string
		var data interface{}
		var err error
		queryParams := retQueryParams(filter)
		ctx, client := getOrCreateClient()
		userId := args[0]
		if len(args) == 2 {
			clientId = args[1]
			log.Printf("Listing grants for user %s, client %s, in %s", userId, clientId, viper.GetString("org"))
			// Get data
			data, _, err = client.User.ListGrantsForUserAndClient(ctx, userId, clientId, queryParams)
		} else {
			log.Printf("Listing grants for user %s in %s", userId, viper.GetString("org"))
			// Get data
			data, _, err = client.User.ListUserGrants(ctx, userId, queryParams)
		}
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin users listclients <userId>
//
var listClientsCmd = &cobra.Command{
	Use:   "listclients <userId>",
	Short: "Lists all client resources for which the specified user has grants or tokens.",
	Long:  `Lists all client resources for which the specified user has grants or tokens.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Listing clients for user %s in %s", userId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.User.ListUserClients(ctx, userId)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin users listgrouptargets <userId> <roleId>
//
var listGroupTargetsCmd = &cobra.Command{
	Use:   "listgrouptargets <userId> <roleId>",
	Short: "List Group Targets for a given User in a specified Role.",
	Long:  `List Group Targets for a given User in a specified Role.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		roleId := args[1]
		queryParams := retQueryParams(filter)
		log.Printf("Listing group targets for user %s, role %s, in %s", userId, roleId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.User.ListGroupTargetsForRole(ctx, userId, roleId, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin users listrefreshtokens <userId> <clientId>
//
var listRefreshTokensCmd = &cobra.Command{
	Use:   "listrefreshtokens <userId> <clientId>",
	Short: "Lists all refresh tokens issued for the specified User and Client.",
	Long:  `Lists all refresh tokens issued for the specified User and Client.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		clientId := args[1]
		queryParams := retQueryParams(filter)
		log.Printf("Listing refresh tokens for user %s, client %s, in %s", userId, clientId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.User.ListRefreshTokensForUserAndClient(ctx, userId, clientId, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin users listgroups <userId>
//
var listUserGroupsCmd = &cobra.Command{
	Use:   "listgroups <userId>",
	Short: "Fetches the groups of which the user is a member.",
	Long:  `Fetches the groups of which the user is a member.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Listing groups for user %s in %s", userId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.User.ListUserGroups(ctx, userId)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin users listidps <userId>
//
var listIdentityProvidersCmd = &cobra.Command{
	Use:   "listidps <userId>",
	Short: "Lists the Identity Providers (IdPs) associated with the user.",
	Long:  `Lists the Identity Providers (IdPs) associated with the user.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Listing identity providers for user %s in %s", userId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.User.ListUserIdentityProviders(ctx, userId)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin users getlinkedobjects <userId> <relationshipName>
//
var getLinkedObjectsCmd = &cobra.Command{
	Use:   "getlinkedobjects <userId> <relationshipName>",
	Short: "Get linked objects for a user, relationshipName can be a primary or associated relationship name.",
	Long:  `Get linked objects for a user, relationshipName can be a primary or associated relationship name.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		relationshipName := args[1]
		queryParams := retQueryParams(filter)
		log.Printf("Getting linked objects for user %s, relationshipName %s, in %s", userId, relationshipName, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.User.GetLinkedObjectsForUser(ctx, userId, relationshipName, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin users getrefreshtoken <userId> <clientId> <tokenId>
//
var getRefreshTokenCmd = &cobra.Command{
	Use:   "getrefreshtoken <userId> <clientId> <tokenId>",
	Short: "Gets a refresh token issued for the specified User and Client.",
	Long:  `Gets a refresh token issued for the specified User and Client.`,
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		clientId := args[1]
		tokenId := args[2]
		queryParams := retQueryParams(filter)
		log.Printf("Getting refresh token for user %s, client %s, tokenId %s, in %s", userId, clientId, tokenId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.User.GetRefreshTokenForUserAndClient(ctx, userId, clientId, tokenId, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

//
// okta-admin users getusergrant <userId> <grantId>
//
var getUserGrantCmd = &cobra.Command{
	Use:   "getusergrant <userId> <grantId>",
	Short: "Gets a grant for the specified user.",
	Long:  `Gets a grant for the specified user.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		grantId := args[1]
		queryParams := retQueryParams(filter)
		log.Printf("Getting user grant for user %s, grant %s, in %s", userId, grantId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		data, _, err := client.User.GetUserGrant(ctx, userId, grantId, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			retResults(data, jsonquery, format)
		}
	},
}

/*
ActivateUser
AddAllAppsAsTargetToRole
AddApplicationTargetToAdminRoleForUser
AddApplicationTargetToAppAdminRoleForUser
AddGroupTargetToRole
AssignRoleToUser
ChangePassword
ChangeRecoveryQuestion
ClearUserSessions
CreateUser
DeactivateOrDeleteUser
DeactivateUser
ExpirePassword
ExpirePasswordAndGetTemporaryPassword
ForgotPasswordGenerateOneTimeToken
ForgotPasswordSetNewPassword
PartialUpdateUser
ReactivateUser
RemoveApplicationTargetFromAdministratorRoleForUser
RemoveApplicationTargetFromApplicationAdministratorRoleForUser
RemoveGroupTargetFromRole
RemoveLinkedObjectForUser
RemoveRoleFromUser
ResetFactors
ResetPassword
RevokeGrantsForUserAndClient
RevokeTokenForUserAndClient
RevokeTokensForUserAndClient
RevokeUserGrant
RevokeUserGrants
SetLinkedObjectForUser
SuspendUser
UnlockUser
UnsuspendUser
UpdateUser
*/

func init() {
	rootCmd.AddCommand(usersCmd)
	// add sub commands
	usersCmd.AddCommand(listUsersCmd)
	usersCmd.AddCommand(getUserCmd)
	usersCmd.AddCommand(listAppLinksCmd)
	usersCmd.AddCommand(listAppTgtsCmd)
	usersCmd.AddCommand(listRolesCmd)
	usersCmd.AddCommand(listGrantsCmd)
	usersCmd.AddCommand(listClientsCmd)
	usersCmd.AddCommand(listGroupTargetsCmd)
	usersCmd.AddCommand(listRefreshTokensCmd)
	usersCmd.AddCommand(listUserGroupsCmd)
	usersCmd.AddCommand(listIdentityProvidersCmd)
	usersCmd.AddCommand(getLinkedObjectsCmd)
	usersCmd.AddCommand(getRefreshTokenCmd)
	usersCmd.AddCommand(getUserGrantCmd)

	// add flags for sub commands
	//listUsersCmd.Flags().StringVarP(&filter, "filter", "f", "", "filter expression to filter results (e.g. 'status eq \\\"ACTIVE\\\"')")
	//listUsersCmd.Flags().StringVarP(&jsonquery, "jsonquery", "q", "", "Json query to extract specified fields from a response object ()")

	generateMarkdownDocs(usersCmd, "./docs/users/")

}
