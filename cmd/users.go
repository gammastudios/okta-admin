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
	"fmt"
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
		idps, _, err := client.User.ListUsers(ctx, queryParams)
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
GetLinkedObjectsForUser
GetRefreshTokenForUserAndClient
GetUser
GetUserGrant
ListAppLinks
ListApplicationTargetsForApplicationAdministratorRoleForUser
ListAssignedRolesForUser
ListGrantsForUserAndClient
ListGroupTargetsForRole
ListRefreshTokensForUserAndClient
ListUserClients
ListUserGrants
ListUserGroups
ListUserIdentityProviders
ListUsers
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

//
// okta-admin users get
//
var getUserCmd = &cobra.Command{
	Use:   "get",
	Short: "Echo anything to the screen more times",
	Long: `echo things multiple times back to the user by providing
a count and a string.`,
	//Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("get user called")
	},
}

func init() {
	rootCmd.AddCommand(usersCmd)
	// add sub commands
	usersCmd.AddCommand(listUsersCmd)
	usersCmd.AddCommand(getUserCmd)

	// add flags for sub commands
	listUsersCmd.Flags().StringVarP(&filter, "filter", "f", "", "filter expression to filter results (e.g. 'status eq \\\"ACTIVE\\\"')")
	listUsersCmd.Flags().StringVarP(&jsonquery, "jsonquery", "q", "", "Json query to extract specified fields from a response object ()")

	generateMarkdownDocs(usersCmd, "./docs/users/")

}
