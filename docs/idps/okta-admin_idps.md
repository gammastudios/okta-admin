## okta-admin idps

Provides operations to manage federations with external Identity Providers (IdP).

### Synopsis

Provides operations to manage federations with external Identity Providers (IdP). For example, your app can support signing in with credentials from Apple, Facebook, Google, LinkedIn, Microsoft, an enterprise IdP using SAML 2.0, or an IdP using the OpenID Connect (OIDC) protocol. Examples include:

okta-admin idps list
		

### Options

```
  -h, --help   help for idps
```

### SEE ALSO

* [okta-admin](okta-admin.md)	 - A brief description of your application
* [okta-admin idps activate](okta-admin_idps_activate.md)	 - Activates  an active IdP.
* [okta-admin idps clonekey](okta-admin_idps_clonekey.md)	 - Clones a X.509 certificate for an IdP signing key credential from a source IdP to target IdP.
* [okta-admin idps create](okta-admin_idps_create.md)	 - Adds a new IdP to your organization.
* [okta-admin idps createkey](okta-admin_idps_createkey.md)	 - Adds a new X.509 certificate credential to the IdP key store.
* [okta-admin idps createmsft](okta-admin_idps_createmsft.md)	 - Adds a new Microsoft SSO IdP to your organization.
* [okta-admin idps deactivate](okta-admin_idps_deactivate.md)	 - Deactivates an active IdP.
* [okta-admin idps delete](okta-admin_idps_delete.md)	 - Removes an IdP from your organization.
* [okta-admin idps deletekey](okta-admin_idps_deletekey.md)	 - Deletes a specific IdP Key Credential by KEYID if it is not currently being used by an Active or Inactive IdP.
* [okta-admin idps generatecsr](okta-admin_idps_generatecsr.md)	 - Generates a new key pair and returns a Certificate Signing Request for it.
* [okta-admin idps generatekey](okta-admin_idps_generatekey.md)	 - Generates a new X.509 certificate for an IdP signing key credential to be used for signing assertions sent to the IdP.
* [okta-admin idps get](okta-admin_idps_get.md)	 - Fetches an IdP by ID.
* [okta-admin idps getcsr](okta-admin_idps_getcsr.md)	 - Gets a specific Certificate Signing Request model by id.
* [okta-admin idps getkey](okta-admin_idps_getkey.md)	 - Gets a specific IdP Key Credential by KEYID.
* [okta-admin idps getkeybyidp](okta-admin_idps_getkeybyidp.md)	 - Gets a specific IdP Key Credential by KEYID
* [okta-admin idps getuser](okta-admin_idps_getuser.md)	 - Fetches a linked IdP user by ID.
* [okta-admin idps linkuser](okta-admin_idps_linkuser.md)	 - Links an Okta user to an existing Social Identity Provider.
* [okta-admin idps list](okta-admin_idps_list.md)	 - Enumerates IdPs in your organization with pagination.
* [okta-admin idps listcsrs](okta-admin_idps_listcsrs.md)	 - Enumerates Certificate Signing Requests for an IdP.
* [okta-admin idps listkeys](okta-admin_idps_listkeys.md)	 - Enumerates keys or signing key credentials for an IdP if specified.
* [okta-admin idps listsocialauthtokens](okta-admin_idps_listsocialauthtokens.md)	 - Fetches the tokens minted by the Social Authentication Provider when the user authenticates with Okta via Social Auth.
* [okta-admin idps listusers](okta-admin_idps_listusers.md)	 - Find all the users linked to an identity provider.
* [okta-admin idps publishcert](okta-admin_idps_publishcert.md)	 - Update the Certificate Signing Request with a signed X.509 certificate and add it into the signing key credentials for the IdP.
* [okta-admin idps revokecsr](okta-admin_idps_revokecsr.md)	 - Revoke a Certificate Signing Request and delete the key pair from the IdP.
* [okta-admin idps unlinkuser](okta-admin_idps_unlinkuser.md)	 - Removes the link between the Okta user and the IdP user.
* [okta-admin idps update](okta-admin_idps_update.md)	 - Updates the configuration for an IdP.

###### Auto generated by spf13/cobra on 29-May-2021
