## okta-admin users

The Okta User API provides operations to manage users in your organization.

### Synopsis


The Okta User API provides operations to manage users in your organization. For example:

okta-admin users list
okta-admin users create
	

### Options

```
  -h, --help   help for users
```

### Options inherited from parent commands

```
      --config string      config file (default is $HOME/.okta-admin.yaml)
  -f, --filter string      filter expression to filter results (e.g. 'status eq \"ACTIVE\"')
      --format             format (pretty-print) json output
  -q, --jsonquery string   Json query to extract specified fields from a response object ()
```

### SEE ALSO

* [okta-admin](okta-admin.md)	 - A brief description of your application
* [okta-admin users activate](okta-admin_users_activate.md)	 - Activates a user.
* [okta-admin users addallappsastargettorole](okta-admin_users_addallappsastargettorole.md)	 - Add all apps as target to role.
* [okta-admin users addapptgtstoadminroleforuser](okta-admin_users_addapptgtstoadminroleforuser.md)	 - Add App Instance Target to App Administrator Role given to a User.
* [okta-admin users addgrouptgttorole](okta-admin_users_addgrouptgttorole.md)	 - Adds group target from role for a user.
* [okta-admin users assignrole](okta-admin_users_assignrole.md)	 - Assigns a role to a user.
* [okta-admin users changepwd](okta-admin_users_changepwd.md)	 - Changes a user password.
* [okta-admin users changerecoveryquestion](okta-admin_users_changerecoveryquestion.md)	 - Changes a users recovery question and answer.
* [okta-admin users clearsessions](okta-admin_users_clearsessions.md)	 - Removes all active identity provider sessions.
* [okta-admin users create](okta-admin_users_create.md)	 - Creates a new user in your Okta organization with or without credentials.
* [okta-admin users deactivate](okta-admin_users_deactivate.md)	 - Deactivates a user.
* [okta-admin users delete](okta-admin_users_delete.md)	 - Deletes a user permanently.
* [okta-admin users expirepwd](okta-admin_users_expirepwd.md)	 - Changes a user password.
* [okta-admin users forgotpwd](okta-admin_users_forgotpwd.md)	 - Sets a new password or generates a one-time token (OTT) that can be used to reset a users password.
* [okta-admin users get](okta-admin_users_get.md)	 - Fetches a user from your Okta organization.
* [okta-admin users getlinkedobjects](okta-admin_users_getlinkedobjects.md)	 - Get linked objects for a user, relationshipName can be a primary or associated relationship name.
* [okta-admin users getrefreshtoken](okta-admin_users_getrefreshtoken.md)	 - Gets a refresh token issued for the specified User and Client.
* [okta-admin users getusergrant](okta-admin_users_getusergrant.md)	 - Gets a grant for the specified user.
* [okta-admin users list](okta-admin_users_list.md)	 - Lists users in your organization.
* [okta-admin users listapplinks](okta-admin_users_listapplinks.md)	 - Fetches appLinks for all direct or indirect (via group membership) assigned applications.
* [okta-admin users listapptargets](okta-admin_users_listapptargets.md)	 - Lists all App targets for an APP_ADMIN Role assigned to a User.
* [okta-admin users listclients](okta-admin_users_listclients.md)	 - Lists all client resources for which the specified user has grants or tokens.
* [okta-admin users listgrants](okta-admin_users_listgrants.md)	 - Lists all grants for a specified user and client if specified.
* [okta-admin users listgroups](okta-admin_users_listgroups.md)	 - Fetches the groups of which the user is a member.
* [okta-admin users listgrouptargets](okta-admin_users_listgrouptargets.md)	 - List Group Targets for a given User in a specified Role.
* [okta-admin users listidps](okta-admin_users_listidps.md)	 - Lists the Identity Providers (IdPs) associated with the user.
* [okta-admin users listrefreshtokens](okta-admin_users_listrefreshtokens.md)	 - Lists all refresh tokens issued for the specified User and Client.
* [okta-admin users listroles](okta-admin_users_listroles.md)	 - Lists all roles assigned to a user.
* [okta-admin users partialupdate](okta-admin_users_partialupdate.md)	 - Update a users profile and/or credentials.
* [okta-admin users reactivate](okta-admin_users_reactivate.md)	 - Reactivates a user.
* [okta-admin users removeapptarget](okta-admin_users_removeapptarget.md)	 - Remove App Instance Target to App Administrator Role given to a User.
* [okta-admin users removegrouptgtfromrole](okta-admin_users_removegrouptgtfromrole.md)	 - Removes group target from role for a user.
* [okta-admin users removelinkedobject](okta-admin_users_removelinkedobject.md)	 - Delete linked objects for a user, relationshipName can be ONLY a primary relationship name.
* [okta-admin users removerole](okta-admin_users_removerole.md)	 - Unassigns a role from a user.
* [okta-admin users resetfactors](okta-admin_users_resetfactors.md)	 - This operation resets all factors for the specified user.
* [okta-admin users resetpwd](okta-admin_users_resetpwd.md)	 - Generates a one-time token (OTT) that can be used to reset a users password.
* [okta-admin users revokegrant](okta-admin_users_revokegrant.md)	 - Revokes one grant or all grants for a specified user.
* [okta-admin users revokegrants](okta-admin_users_revokegrants.md)	 - Revokes all grants for the specified user and client.
* [okta-admin users revoketoken](okta-admin_users_revoketoken.md)	 - Revokes the specified refresh token or all tokens for the user.
* [okta-admin users setlinkedobject](okta-admin_users_setlinkedobject.md)	 - Sets linked objects for a associatedUserId, primaryRelationshipName and primaryUserId.
* [okta-admin users suspend](okta-admin_users_suspend.md)	 - Suspends a user.
* [okta-admin users unlock](okta-admin_users_unlock.md)	 - Unlocks a user with a LOCKED_OUT status.
* [okta-admin users unsuspend](okta-admin_users_unsuspend.md)	 - Unsuspends a user.
* [okta-admin users update](okta-admin_users_update.md)	 - Update a users profile and/or credentials using strict-update semantics.

###### Auto generated by spf13/cobra on 30-May-2021
