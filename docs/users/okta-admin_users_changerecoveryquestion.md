## okta-admin users changerecoveryquestion

Changes a users recovery question and answer.

### Synopsis

Changes a user recovery question and answer credential by validating the users current password. 
	This operation can only be performed on users in **STAGED**, **ACTIVE** or **RECOVERY** status that have a valid password credential.

```
okta-admin users changerecoveryquestion <userId> <jsonBody> [flags]
```

### Options

```
  -h, --help   help for changerecoveryquestion
```

### Options inherited from parent commands

```
      --config string      config file (default is $HOME/.okta-admin.yaml)
  -f, --filter string      filter expression to filter results (e.g. 'status eq \"ACTIVE\"')
      --format             format (pretty-print) json output
  -q, --jsonquery string   Json query to extract specified fields from a response object ()
```

### SEE ALSO

* [okta-admin users](okta-admin_users.md)	 - The Okta User API provides operations to manage users in your organization.

###### Auto generated by spf13/cobra on 30-May-2021