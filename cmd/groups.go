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

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// groupsCmd represents the groups command
var groupsCmd = &cobra.Command{
	Use:   "groups",
	Short: "The Okta Groups API provides operations to manage Okta Groups and their user members for your organization.",
	Long: `
The Okta Groups API provides operations to manage Okta Groups and their user members for your organization. For example:

okta-admin groups list
okta-admin groups create
	`,
	Args: cobra.MinimumNArgs(1),
}

// okta-admin groups list
var listGroupsCmd = &cobra.Command{
	Use:   "list",
	Short: "Lists groups in your organization.",
	Long:  `Lists groups in your organization.`,
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		queryParams := retQueryParams(filter)
		log.Printf("Listing groups in %s", viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Group.ListGroups(ctx, queryParams))
	},
}

// okta-admin groups listusers
var listGroupUsersCmd = &cobra.Command{
	Use:   "listusers",
	Short: "Enumerates all users that are a member of a group.",
	Long:  `Enumerates all users that are a member of a group.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		groupId := args[0]
		queryParams := retQueryParams(filter)
		log.Printf("Listing groups in %s", viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.Group.ListGroupUsers(ctx, groupId, queryParams))
	},
}

// okta-admin groups create
var createGroupCmd = &cobra.Command{
	Use:   "create <name> [<description>]",
	Short: "Adds a new group with OKTA_GROUP type to your organization.",
	Long:  `Adds a new group with OKTA_GROUP type to your organization.`,
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		description := ""
		if len(args) == 2 {
			description = args[1]
		}
		log.Printf("Creating new group %s in %s", name, viper.GetString("org"))
		gp := &okta.GroupProfile{
			Name:        name,
			Description: description,
		}
		g := &okta.Group{
			Profile: gp,
		}
		ctx, client := getOrCreateClient()
		processOutput(client.Group.CreateGroup(ctx, *g))
	},
}

// okta-admin groups adduser <groupId> <userId>
var addUsertoGroupCmd = &cobra.Command{
	Use:   "adduser <groupId> <userId>",
	Short: "Adds a user to a group with OKTA_GROUP type.",
	Long:  `Adds a user to a group with OKTA_GROUP type.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		groupId := args[0]
		userId := args[1]
		log.Printf("Adding user %s to group %s in %s", userId, groupId, viper.GetString("org"))
		ctx, client := getOrCreateClient()
		resp, err := client.Group.AddUserToGroup(ctx, groupId, userId)
		processOutput(nil, resp, err)
	},
}

/* groups client.Group
ActivateGroupRule
AddApplicationInstanceTargetToAppAdminRoleGivenToGroup
AddApplicationTargetToAdminRoleGivenToGroup
AddGroupTargetToGroupAdministratorRoleForGroup
AssignRoleToGroup
CreateGroupRule
DeactivateGroupRule
DeleteGroup
DeleteGroupRule
GetGroup
GetGroupRule
GetRole
ListApplicationTargetsForApplicationAdministratorRoleForGroup
ListAssignedApplicationsForGroup
ListGroupAssignedRoles
ListGroupRules
ListGroupTargetsForGroupRole
RemoveApplicationTargetFromAdministratorRoleGivenToGroup
RemoveApplicationTargetFromApplicationAdministratorRoleGivenToGroup
RemoveGroupTargetFromGroupAdministratorRoleGivenToGroup
RemoveRoleFromGroup
RemoveUserFromGroup
UpdateGroup
UpdateGroupRule
*/

func init() {
	rootCmd.AddCommand(groupsCmd)
	groupsCmd.AddCommand(listGroupsCmd)
	groupsCmd.AddCommand(listGroupUsersCmd)
	groupsCmd.AddCommand(createGroupCmd)
	groupsCmd.AddCommand(addUsertoGroupCmd)
	generateMarkdownDocs(groupsCmd, "./docs/groups/")
}
