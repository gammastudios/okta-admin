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
		users, _, err := client.User.ListUsers(ctx, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			b, err := json.Marshal(users)
			if err != nil {
				panic(err)
			} else {
				retResults(b, jsonquery)
			}
		}
	},
}

//
// okta-admin users get <userId>
//
var getUserCmd = &cobra.Command{
	Use:   "get",
	Short: "Fetches a user from your Okta organization.",
	Long:  `Fetches a user from your Okta organization.`,
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Fetching user %s in %s", userId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		user, _, err := client.User.GetUser(ctx, userId)
		if err != nil {
			log.Println(err)
		} else {
			b, err := json.Marshal(user)
			if err != nil {
				panic(err)
			} else {
				retResults(b, jsonquery)
			}
		}
	},
}

//
// okta-admin users listapplinks <userId>
//
var listAppLinksCmd = &cobra.Command{
	Use:   "listapplinks",
	Short: "Fetches appLinks for all direct or indirect (via group membership) assigned applications.",
	Long:  `Fetches appLinks for all direct or indirect (via group membership) assigned applications.`,
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Fetching appLinks for user %s in %s", userId, viper.GetString("org"))
		// Get data
		ctx, client := getOrCreateClient()
		applinks, _, err := client.User.ListAppLinks(ctx, userId)
		if err != nil {
			log.Println(err)
		} else {
			b, err := json.Marshal(applinks)
			if err != nil {
				panic(err)
			} else {
				retResults(b, jsonquery)
			}
		}
	},
}

//
// okta-admin users listapptargets <userId> <roleId>
//
var listAppTgtsCmd = &cobra.Command{
	Use:   "listapptargets",
	Short: "Lists all App targets for an APP_ADMIN Role assigned to a User.",
	Long: `Lists all App targets for an APP_ADMIN Role assigned to a User. 
This methods return list may include full Applications or Instances. 
The response for an instance will have an ID value, while Application will not have an ID.`,
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		roleId := args[1]
		log.Printf("Listing App targets for user %s, role %s, in %s", userId, roleId, viper.GetString("org"))
		queryParams := retQueryParams(filter)
		// Get data
		ctx, client := getOrCreateClient()
		apptargets, _, err := client.User.ListApplicationTargetsForApplicationAdministratorRoleForUser(ctx, userId, roleId, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			b, err := json.Marshal(apptargets)
			if err != nil {
				panic(err)
			} else {
				retResults(b, jsonquery)
			}
		}
	},
}

//
// okta-admin users listroles <userId> <roleId>
//
var listRolesCmd = &cobra.Command{
	Use:   "listroles",
	Short: "Lists all roles assigned to a user.",
	Long:  `Lists all roles assigned to a user.`,
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Listing roles for user %s in %s", userId, viper.GetString("org"))
		queryParams := retQueryParams(filter)
		// Get data
		ctx, client := getOrCreateClient()
		roles, _, err := client.User.ListAssignedRolesForUser(ctx, userId, queryParams)
		if err != nil {
			log.Println(err)
		} else {
			b, err := json.Marshal(roles)
			if err != nil {
				panic(err)
			} else {
				retResults(b, jsonquery)
			}
		}
	},
}

/*
ListGrantsForUserAndClient
ListGroupTargetsForRole
ListRefreshTokensForUserAndClient
ListUserClients
ListUserGrants
ListUserGroups
ListUserIdentityProviders
GetLinkedObjectsForUser
GetRefreshTokenForUserAndClient
GetUserGrant
*/

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

	// add flags for sub commands
	listUsersCmd.Flags().StringVarP(&filter, "filter", "f", "", "filter expression to filter results (e.g. 'status eq \\\"ACTIVE\\\"')")
	listUsersCmd.Flags().StringVarP(&jsonquery, "jsonquery", "q", "", "Json query to extract specified fields from a response object ()")

	generateMarkdownDocs(usersCmd, "./docs/users/")

}
