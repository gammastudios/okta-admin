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
// Query Operations (return data)
//

// okta-admin users list
var listUsersCmd = &cobra.Command{
	Use:   "list",
	Short: "Lists users in your organization.",
	Long:  `Lists users in your organization.`,
	Run: func(cmd *cobra.Command, args []string) {
		queryParams := retQueryParams(filter)
		log.Printf("Listing users in %s", viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.User.ListUsers(ctx, queryParams))
	},
}

// okta-admin users get <userId>
var getUserCmd = &cobra.Command{
	Use:   "get <userId>",
	Short: "Fetches a user from your Okta organization.",
	Long:  `Fetches a user from your Okta organization.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Fetching user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.User.GetUser(ctx, userId))
	},
}

// okta-admin users listapplinks <userId>
var listAppLinksCmd = &cobra.Command{
	Use:   "listapplinks <userId>",
	Short: "Fetches appLinks for all direct or indirect (via group membership) assigned applications.",
	Long:  `Fetches appLinks for all direct or indirect (via group membership) assigned applications.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Fetching appLinks for user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.User.ListAppLinks(ctx, userId))
	},
}

// okta-admin users listapptargets <userId> <roleId>
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
		queryParams := retQueryParams(filter)
		log.Printf("Listing App targets for user %s, role %s, in %s", userId, roleId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.User.ListApplicationTargetsForApplicationAdministratorRoleForUser(ctx, userId, roleId, queryParams))
	},
}

// okta-admin users listroles <userId>
var listRolesCmd = &cobra.Command{
	Use:   "listroles <userId>",
	Short: "Lists all roles assigned to a user.",
	Long:  `Lists all roles assigned to a user.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Listing roles for user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.User.ListAssignedRolesForUser(ctx, userId, queryParams))
	},
}

// okta-admin users listgrants <userId> [<clientId>]
var listGrantsCmd = &cobra.Command{
	// overloaded command
	Use:   "listgrants <userId> [<clientId>]",
	Short: "Lists all grants for a specified user and client if specified.",
	Long:  `Lists all grants for a specified user and client if specified.`,
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		var clientId string
		userId := args[0]
		queryParams := retQueryParams(filter)
		ctx, client := getOrCreateClient()
		if len(args) == 2 {
			clientId = args[1]
			log.Printf("Listing grants for user %s, client %s, in %s", userId, clientId, viper.GetString("org"))
			processOutput(client.User.ListGrantsForUserAndClient(ctx, userId, clientId, queryParams))
		} else {
			log.Printf("Listing grants for user %s in %s", userId, viper.GetString("org"))
			processOutput(client.User.ListUserGrants(ctx, userId, queryParams))
		}
	},
}

// okta-admin users listclients <userId>
var listClientsCmd = &cobra.Command{
	Use:   "listclients <userId>",
	Short: "Lists all client resources for which the specified user has grants or tokens.",
	Long:  `Lists all client resources for which the specified user has grants or tokens.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Listing clients for user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.User.ListUserClients(ctx, userId))
	},
}

// okta-admin users listgrouptargets <userId> <roleId>
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
		ctx, client := getOrCreateClient()
		processOutput(client.User.ListGroupTargetsForRole(ctx, userId, roleId, queryParams))
	},
}

// okta-admin users listrefreshtokens <userId> <clientId>
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
		ctx, client := getOrCreateClient()
		processOutput(client.User.ListRefreshTokensForUserAndClient(ctx, userId, clientId, queryParams))
	},
}

// okta-admin users listgroups <userId>
var listUserGroupsCmd = &cobra.Command{
	Use:   "listgroups <userId>",
	Short: "Fetches the groups of which the user is a member.",
	Long:  `Fetches the groups of which the user is a member.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Listing groups for user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.User.ListUserGroups(ctx, userId))
	},
}

// okta-admin users listidps <userId>
var listIdentityProvidersCmd = &cobra.Command{
	Use:   "listidps <userId>",
	Short: "Lists the Identity Providers (IdPs) associated with the user.",
	Long:  `Lists the Identity Providers (IdPs) associated with the user.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Listing identity providers for user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.User.ListUserIdentityProviders(ctx, userId))
	},
}

// okta-admin users getlinkedobjects <userId> <relationshipName>
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
		ctx, client := getOrCreateClient()
		processOutput(client.User.GetLinkedObjectsForUser(ctx, userId, relationshipName, queryParams))
	},
}

// okta-admin users getrefreshtoken <userId> <clientId> <tokenId>
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
		ctx, client := getOrCreateClient()
		processOutput(client.User.GetRefreshTokenForUserAndClient(ctx, userId, clientId, tokenId, queryParams))
	},
}

// okta-admin users getusergrant <userId> <grantId>
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
		ctx, client := getOrCreateClient()
		processOutput(client.User.GetUserGrant(ctx, userId, grantId, queryParams))
	},
}

//
// Action Operations (return resp code)
//

// okta-admin users activate <userId>
var activateUserCmd = &cobra.Command{
	Use:   "activate <userId>",
	Short: "Activates a user.",
	Long:  `Activates a user. This operation can only be performed on users with a STAGED status. Activation of a user is an asynchronous operation. The user will have the transitioningToStatus property with a value of ACTIVE during activation to indicate that the user hasnt completed the asynchronous operation. The user will have a status of ACTIVE when the activation process is complete.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Activating user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.User.ActivateUser(ctx, userId, queryParams))
	},
}

// okta-admin users deactivate <userId>
var deactivateUserCmd = &cobra.Command{
	Use:   "deactivate <userId>",
	Short: "Deactivates a user.",
	Long:  `Deactivates a user. This operation can only be performed on users that do not have a DEPROVISIONED status. Deactivation of a user is an asynchronous operation. The user will have the transitioningToStatus property with a value of DEPROVISIONED during deactivation to indicate that the user hasnt completed the asynchronous operation. The user will have a status of DEPROVISIONED when the deactivation process is complete.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Deactivating user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.User.DeactivateUser(ctx, userId, queryParams)
		processOutput(nil, resp, err)
	},
}

// okta-admin users reactivate <userId>
var reactivateUserCmd = &cobra.Command{
	Use:   "reactivate <userId>",
	Short: "Reactivates a user.",
	Long:  `Reactivates a user. This operation can only be performed on users with a PROVISIONED status. This operation restarts the activation workflow if for some reason the user activation was not completed when using the activationToken from [Activate User](#activate-user).`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Reactivating user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.User.ReactivateUser(ctx, userId, queryParams))
	},
}

// okta-admin users delete <userId>
var deleteUserCmd = &cobra.Command{
	Use:   "delete <userId>",
	Short: "Deletes a user permanently.",
	Long:  `Deletes a user permanently. This operation can only be performed on users that have a DEPROVISIONED status. **This action cannot be recovered!**`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Deleting user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.User.DeactivateOrDeleteUser(ctx, userId, queryParams)
		processOutput(nil, resp, err)
	},
}

// okta-admin users suspend <userId>
var suspendUserCmd = &cobra.Command{
	Use:   "suspend <userId>",
	Short: "Suspends a user.",
	Long:  `Suspends a user. This operation can only be performed on users with an ACTIVE status. The user will have a status of SUSPENDED when the process is complete.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Suspending user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.User.SuspendUser(ctx, userId)
		processOutput(nil, resp, err)
	},
}

// okta-admin users unsuspend <userId>
var unsuspendUserCmd = &cobra.Command{
	Use:   "unsuspend <userId>",
	Short: "Unsuspends a user.",
	Long:  `Unsuspends a user and returns them to the ACTIVE state. This operation can only be performed on users that have a SUSPENDED status.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Unsuspending user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.User.UnsuspendUser(ctx, userId)
		processOutput(nil, resp, err)
	},
}

// okta-admin users unlock <userId>
var unlockUserCmd = &cobra.Command{
	Use:   "unlock <userId>",
	Short: "Unlocks a user with a LOCKED_OUT status.",
	Long:  `Unlocks a user with a LOCKED_OUT status and returns them to ACTIVE status. Users will be able to login with their current password.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Unlocking user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.User.UnlockUser(ctx, userId)
		processOutput(nil, resp, err)
	},
}

// okta-admin users changepwd <userId> <jsonBody>
var changeUserPwdCmd = &cobra.Command{
	Use:   "changepwd <userId> <jsonBody>",
	Short: "Changes a user password.",
	Long:  `Changes a user password by validating the users current password. This operation can only be performed on users in STAGED, ACTIVE, PASSWORD_EXPIRED, or RECOVERY status that have a valid password credential`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		jsonBody := args[1]
		queryParams := retQueryParams(filter)
		log.Printf("Changing password for user %s in %s", userId, viper.GetString("org"))
		var body okta.ChangePasswordRequest
		json.Unmarshal([]byte(jsonBody), &body)
		ctx, client := getOrCreateClient()
		processOutput(client.User.ChangePassword(ctx, userId, body, queryParams))
	},
}

// okta-admin users expirepwd <userId> [<tempPassword: true|false>]
var expirePwdCmd = &cobra.Command{
	Use:   "expirepwd <userId> [<tempPassword: true|false>]",
	Short: "Changes a user password.",
	Long:  `Changes a user password by validating the users current password. This operation can only be performed on users in STAGED, ACTIVE, PASSWORD_EXPIRED, or RECOVERY status that have a valid password credential`,
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		var tmpPwd bool
		userId := args[0]
		if len(args) == 2 {
			tempPassword := args[1]
			switch tempPassword {
			case "true":
				tmpPwd = true
			default:
				tmpPwd = false
			}
		}
		log.Printf("Expiring password for user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		if tmpPwd {
			processOutput(client.User.ExpirePasswordAndGetTemporaryPassword(ctx, userId))
		} else {
			processOutput(client.User.ExpirePassword(ctx, userId))
		}
	},
}

// okta-admin users resetpwd <userId>
var resetPwdCmd = &cobra.Command{
	Use:   "resetpwd <userId>",
	Short: "Generates a one-time token (OTT) that can be used to reset a users password.",
	Long:  `Generates a one-time token (OTT) that can be used to reset a users password.  The OTT link can be automatically emailed to the user or returned to the API caller and distributed using a custom flow.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Generating OTT for password reset for user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.User.ResetPassword(ctx, userId, queryParams))
	},
}

// okta-admin users forgotpwd <userId> [<jsonBody>]
var forgotPwdCmd = &cobra.Command{
	// overloaded command
	Use:   "forgotpwd <userId> [<jsonBody>]",
	Short: "Sets a new password or generates a one-time token (OTT) that can be used to reset a users password.",
	Long: `[if jsonBody is not supplied] Generates a one-time token (OTT) that can be used to reset a users password.
	[if a jsonBody is supplied] Sets a new password for a user by validating the user&#x27;s answer to their current recovery question.
	`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		var userId string
		userId = args[0]
		queryParams := retQueryParams(filter)
		ctx, client := getOrCreateClient()
		if len(args) == 2 {
			jsonBody := args[1]
			var body okta.UserCredentials
			json.Unmarshal([]byte(jsonBody), &body)
			log.Printf("Setting new password for user %s in %s", userId, viper.GetString("org"))
			processOutput(client.User.ForgotPasswordSetNewPassword(ctx, userId, body, queryParams))
		} else {
			log.Printf("Generating one time token (OTT) for user %s in %s", userId, viper.GetString("org"))
			processOutput(client.User.ForgotPasswordGenerateOneTimeToken(ctx, userId, queryParams))
		}
	},
}

// okta-admin users changerecoveryquestion <userId> <jsonBody>
var changeRecoveryQuestionCmd = &cobra.Command{
	Use:   "changerecoveryquestion <userId> <jsonBody>",
	Short: "Changes a users recovery question and answer.",
	Long: `Changes a user recovery question and answer credential by validating the users current password. 
	This operation can only be performed on users in **STAGED**, **ACTIVE** or **RECOVERY** status that have a valid password credential.`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		jsonBody := args[1]
		var body okta.UserCredentials
		json.Unmarshal([]byte(jsonBody), &body)
		log.Printf("Changing recovery question for user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.User.ChangeRecoveryQuestion(ctx, userId, body))
	},
}

// okta-admin users resetfactors <userId>
var resetFactorsCmd = &cobra.Command{
	Use:   "resetfactors <userId>",
	Short: "This operation resets all factors for the specified user.",
	Long: `This operation resets all factors for the specified user. 
	All MFA factor enrollments returned to the unenrolled state. The users status remains ACTIVE. 
	This link is present only if the user is currently enrolled in one or more MFA factors.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		log.Printf("Reseting factors for user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.User.ResetFactors(ctx, userId)
		processOutput(nil, resp, err)
	},
}

// okta-admin users assignrole <userId> <jsonBody>
var assignRoleCmd = &cobra.Command{
	Use:   "assignrole <userId> <jsonBody>",
	Short: "Assigns a role to a user.",
	Long:  `Assigns a role to a user.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		jsonBody := args[1]
		queryParams := retQueryParams(filter)
		var body okta.AssignRoleRequest
		json.Unmarshal([]byte(jsonBody), &body)
		log.Printf("Assigning role to user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.User.AssignRoleToUser(ctx, userId, body, queryParams))
	},
}

// okta-admin users clearsessions <userId>
var clearSessionsCmd = &cobra.Command{
	Use:   "clearsessions <userId>",
	Short: "Removes all active identity provider sessions.",
	Long: `Removes all active identity provider sessions. 
	This forces the user to authenticate on the next operation. 
	Optionally revokes OpenID Connect and OAuth refresh and access tokens issued to the user.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Reseting factors for user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.User.ClearUserSessions(ctx, userId, queryParams)
		processOutput(nil, resp, err)
	},
}

// okta-admin users removeapptarget <userId> <roleId> <appName> [<applicationId>]
var removeAppTgtCmd = &cobra.Command{
	// overloaded command
	Use:   "removeapptarget <userId> <roleId> <appName> [<applicationId>]",
	Short: "Remove App Instance Target to App Administrator Role given to a User.",
	Long:  `Remove App Instance Target to App Administrator Role given to a User.`,
	Args:  cobra.RangeArgs(3, 4),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		roleId := args[1]
		appName := args[2]
		ctx, client := getOrCreateClient()
		if len(args) == 4 {
			applicationId := args[3]
			log.Printf("Removing app instance target for user %s, role %s, appname %s, appid %s, in %s", userId, roleId, appName, applicationId, viper.GetString("org"))
			resp, err := client.User.RemoveApplicationTargetFromAdministratorRoleForUser(ctx, userId, roleId, appName, applicationId)
			processOutput(nil, resp, err)
		} else {
			log.Printf("Removing app instance target for user %s, role %s, appname %s, in %s", userId, roleId, appName, viper.GetString("org"))
			resp, err := client.User.RemoveApplicationTargetFromApplicationAdministratorRoleForUser(ctx, userId, roleId, appName)
			processOutput(nil, resp, err)
		}
	},
}

// okta-admin users removegrouptgtfromrole <userId> <roleId> <groupId>
var removeGroupTargetFromRoleCmd = &cobra.Command{
	Use:   "removegrouptgtfromrole <userId> <roleId> <groupId>",
	Short: "Removes group target from role for a user.",
	Long:  `Removes group target from role for a user.`,
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		roleId := args[1]
		groupId := args[2]
		log.Printf("Removing group target %s from role %s for user %s in %s", groupId, roleId, userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.User.RemoveGroupTargetFromRole(ctx, userId, roleId, groupId)
		processOutput(nil, resp, err)
	},
}

// okta-admin users addgrouptgttorole <userId> <roleId> <groupId>
var addGroupTargetToRoleCmd = &cobra.Command{
	Use:   "addgrouptgttorole <userId> <roleId> <groupId>",
	Short: "Adds group target from role for a user.",
	Long:  `Adds group target from role for a user.`,
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		roleId := args[1]
		groupId := args[2]
		log.Printf("Adding group target %s from role %s for user %s in %s", groupId, roleId, userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.User.AddGroupTargetToRole(ctx, userId, roleId, groupId)
		processOutput(nil, resp, err)
	},
}

// okta-admin users removelinkedobject <userId> <relationshipName>
var removeLinkedObjectCmd = &cobra.Command{
	Use:   "removelinkedobject <userId> <relationshipName>",
	Short: "Delete linked objects for a user, relationshipName can be ONLY a primary relationship name.",
	Long:  `Delete linked objects for a user, relationshipName can be ONLY a primary relationship name.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		relationshipName := args[1]
		log.Printf("Deleting linked objects for a user %s, relationshipName %s, in %s", userId, relationshipName, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.User.RemoveLinkedObjectForUser(ctx, userId, relationshipName)
		processOutput(nil, resp, err)
	},
}

// okta-admin users setlinkedobject <associatedUserId> <primaryRelationshipName> <primaryUserId>
var setLinkedObjectCmd = &cobra.Command{
	Use:   "setlinkedobject <associatedUserId> <primaryRelationshipName> <primaryUserId>",
	Short: "Sets linked objects for a associatedUserId, primaryRelationshipName and primaryUserId.",
	Long:  `Sets linked objects for a associatedUserId, primaryRelationshipName and primaryUserId.`,
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		associatedUserId := args[0]
		primaryRelationshipName := args[1]
		primaryUserId := args[2]
		log.Printf("Setting linked object for a associatedUserId %s, primaryRelationshipName %s, primaryUserId %s, in %s", associatedUserId, primaryRelationshipName, primaryUserId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.User.SetLinkedObjectForUser(ctx, associatedUserId, primaryRelationshipName, primaryUserId)
		processOutput(nil, resp, err)
	},
}

// okta-admin users removerole <userId> <roleId>
var removeRoleCmd = &cobra.Command{
	Use:   "removerole <userId> <roleId>",
	Short: "Unassigns a role from a user.",
	Long:  `Unassigns a role from a user.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		roleId := args[1]
		log.Printf("Removing role %s from user %s in %s", roleId, userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.User.RemoveRoleFromUser(ctx, userId, roleId)
		processOutput(nil, resp, err)
	},
}

// okta-admin users revokegrants <userId> <clientId>
var revokeGrantsCmd = &cobra.Command{
	Use:   "revokegrants <userId> <clientId>",
	Short: "Revokes all grants for the specified user and client.",
	Long:  `Revokes all grants for the specified user and client.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		clientId := args[1]
		log.Printf("Revoking grants for user %s, client %s, in %s", userId, clientId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.User.RevokeGrantsForUserAndClient(ctx, userId, clientId)
		processOutput(nil, resp, err)
	},
}

// okta-admin users revoketoken <userId> <clientId> [<tokenId>]
var revokeTokenCmd = &cobra.Command{
	Use:   "revoketoken <userId> <clientId> [<tokenId>]",
	Short: "Revokes the specified refresh token or all tokens for the user.",
	Long: `Revokes all tokens for the specified user and client (if supplied).
	[if no token is supplied] Revokes all refresh tokens issued for the specified User and Client.`,
	Args: cobra.RangeArgs(2, 3),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		clientId := args[1]
		if len(args) == 3 {
			tokenId := args[2]
			log.Printf("Revoking token %s for user %s, client %s, in %s", tokenId, userId, clientId, viper.GetString("org"))
			ctx, client := getOrCreateClient()
			resp, err := client.User.RevokeTokenForUserAndClient(ctx, userId, clientId, tokenId)
			processOutput(nil, resp, err)
		} else {
			log.Printf("Revoking all tokens for user %s, client %s, in %s", userId, clientId, viper.GetString("org"))
			ctx, client := getOrCreateClient()
			resp, err := client.User.RevokeTokensForUserAndClient(ctx, userId, clientId)
			processOutput(nil, resp, err)
		}
	},
}

// okta-admin users revokegrant <userId> [<grantId>]
var revokeGrantCmd = &cobra.Command{
	Use:   "revokegrant <userId> [<grantId>]",
	Short: "Revokes one grant or all grants for a specified user.",
	Long: `Revokes one grant for a specified user (if grantId is supplied).
	[if grantId is not supplied] Revokes all grants for a specified user.`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		if len(args) == 2 {
			grantId := args[1]
			log.Printf("Revoking grant %s for user %s, in %s", grantId, userId, viper.GetString("org"))
			ctx, client := getOrCreateClient()
			resp, err := client.User.RevokeUserGrant(ctx, userId, grantId)
			processOutput(nil, resp, err)
		} else {
			log.Printf("Revoking all grants for user %s, in %s", userId, viper.GetString("org"))
			ctx, client := getOrCreateClient()
			resp, err := client.User.RevokeUserGrants(ctx, userId)
			processOutput(nil, resp, err)
		}
	},
}

// okta-admin users addallappsastargettorole <userId> <roleId>
var addAllAppsAsTargetToRoleCmd = &cobra.Command{
	Use:   "addallappsastargettorole <userId> <roleId>",
	Short: "Add all apps as target to role.",
	Long:  `Add all apps as target to role.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		roleId := args[1]
		log.Printf("Adding all apps as target to role %s for user %s, in %s", roleId, userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.User.AddAllAppsAsTargetToRole(ctx, userId, roleId)
		processOutput(nil, resp, err)
	},
}

// okta-admin users addapptgtstoadminroleforuser <userId> <roleId> <appName> [<applicationId>]
var addAppTgtsToAdminRoleForUserCmd = &cobra.Command{
	Use:   "addapptgtstoadminroleforuser <userId> <roleId> <appName> [<applicationId>]",
	Short: "Add App Instance Target to App Administrator Role given to a User.",
	Long:  `Add App Instance Target to App Administrator Role given to a User.`,
	Args:  cobra.RangeArgs(3, 4),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		roleId := args[1]
		appName := args[2]
		if len(args) == 4 {
			applicationId := args[3]
			log.Printf("Adding App Instance Target to App Administrator Role given for user %s, role %s, appname %s, appid %s, in %s", userId, roleId, appName, applicationId, viper.GetString("org"))
			ctx, client := getOrCreateClient()
			resp, err := client.User.AddApplicationTargetToAppAdminRoleForUser(ctx, userId, roleId, appName, applicationId)
			processOutput(nil, resp, err)
		} else {
			log.Printf("Adding App Instance Target to App Administrator Role given for user %s, role %s, appname %s, in %s", userId, roleId, appName, viper.GetString("org"))
			ctx, client := getOrCreateClient()
			resp, err := client.User.AddApplicationTargetToAdminRoleForUser(ctx, userId, roleId, appName)
			processOutput(nil, resp, err)
		}
	},
}

//
// Mutation Operations (return resp code)
//

// okta-admin users create <jsonBody>
var createUserCmd = &cobra.Command{
	Use:   "create <jsonBody>",
	Short: "Creates a new user in your Okta organization with or without credentials.",
	Long:  `Creates a new user in your Okta organization with or without credentials.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		jsonBody := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Creating new user in %s", viper.GetString("org"))
		ctx, client := getOrCreateClient()
		var body okta.CreateUserRequest
		json.Unmarshal([]byte(jsonBody), &body)
		processOutput(client.User.CreateUser(ctx, body, queryParams))
	},
}

// okta-admin users update <userId> <jsonBody>
var updateUserCmd = &cobra.Command{
	Use:   "update <userId> <jsonBody>",
	Short: "Update a users profile and/or credentials using strict-update semantics.",
	Long:  `Update a users profile and/or credentials using strict-update semantics.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		jsonBody := args[1]
		queryParams := retQueryParams(filter)
		log.Printf("Updating user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		var body okta.User
		json.Unmarshal([]byte(jsonBody), &body)
		processOutput(client.User.UpdateUser(ctx, userId, body, queryParams))
	},
}

// okta-admin users partialupdate <userId> <jsonBody>
var partialUpdateUserCmd = &cobra.Command{
	Use:   "partialupdate <userId> <jsonBody>",
	Short: "Update a users profile and/or credentials.",
	Long:  `Update a users profile and/or credentials.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userId := args[0]
		jsonBody := args[1]
		queryParams := retQueryParams(filter)
		log.Printf("Updating user %s in %s", userId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		var body okta.User
		json.Unmarshal([]byte(jsonBody), &body)
		processOutput(client.User.PartialUpdateUser(ctx, userId, body, queryParams))
	},
}

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
	usersCmd.AddCommand(createUserCmd)
	usersCmd.AddCommand(updateUserCmd)
	usersCmd.AddCommand(partialUpdateUserCmd)
	usersCmd.AddCommand(activateUserCmd)
	usersCmd.AddCommand(deactivateUserCmd)
	usersCmd.AddCommand(reactivateUserCmd)
	usersCmd.AddCommand(deleteUserCmd)
	usersCmd.AddCommand(suspendUserCmd)
	usersCmd.AddCommand(unsuspendUserCmd)
	usersCmd.AddCommand(unlockUserCmd)
	usersCmd.AddCommand(changeUserPwdCmd)
	usersCmd.AddCommand(expirePwdCmd)
	usersCmd.AddCommand(resetPwdCmd)
	usersCmd.AddCommand(forgotPwdCmd)
	usersCmd.AddCommand(changeRecoveryQuestionCmd)
	usersCmd.AddCommand(resetFactorsCmd)
	usersCmd.AddCommand(assignRoleCmd)
	usersCmd.AddCommand(clearSessionsCmd)
	usersCmd.AddCommand(removeAppTgtCmd)
	usersCmd.AddCommand(removeGroupTargetFromRoleCmd)
	usersCmd.AddCommand(addGroupTargetToRoleCmd)
	usersCmd.AddCommand(removeLinkedObjectCmd)
	usersCmd.AddCommand(setLinkedObjectCmd)
	usersCmd.AddCommand(removeRoleCmd)
	usersCmd.AddCommand(revokeGrantsCmd)
	usersCmd.AddCommand(revokeTokenCmd)
	usersCmd.AddCommand(revokeGrantCmd)
	usersCmd.AddCommand(addAllAppsAsTargetToRoleCmd)
	usersCmd.AddCommand(addAppTgtsToAdminRoleForUserCmd)

	// generateMarkdownDocs(usersCmd, "./docs/users/")

}
