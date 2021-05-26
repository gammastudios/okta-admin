# `okta-admin` Command Line Utility

Command line utility to perform administrative tasks for an Okta org.

## Documentation

For information on APIs and sub commands available, see the markdown documents available using the links below:

- [Users API (`users`)](https://github.com/gammastudios/okta-admin/docs/users)
- [Groups API (`groups`)](https://github.com/gammastudios/okta-admin/docs/groups)
- [Applications API (`apps`)](https://github.com/gammastudios/okta-admin/docs/apps)

### Filtering and projecting results

Results from the `okta-admin` utility are returned as string representations of json objects.

Results can be filtered at the remote API using the `--filter` flag for a given command, for instance:

`okta-admin users list --filter 'status eq \"ACTIVE\"'`

would return only the users with a `status` value of `ACTIVE`

Once results are returned they can be further filtered, projected or have other operations performed using the `--jsonquery` flag, for example:

`okta-admin users list --jsonquery '[0]'`

would return the first user in the org

`okta-admin users list --jsonquery '0.profile.email'`

would return the email of the first user in the org (as a scalar value - not an object)

`okta-admin users list --jsonquery '#'`

would return the number of users in the org

`okta-admin users list --jsonquery '#.profile.email'`

would return a list of all users emails in the org

## Prerequisites

- Okta org, see https://www.okta.com/
- API key (generated using the Okta Admin Console)
- Golang compiler

## Instructions

> The following environment variables must be set to run `okta-admin` commands:  `OKTAORGURL` and `OKTAAPITOKEN`

### Build the Application
```bash
go build
```
### Windows Example (Powershell)
```powershell
$env:OKTAORGURL = 'https://avensolutions.okta.com'; $env:OKTAAPITOKEN = 'xxxYOURTOKENHERExxx'; .\okta-admin.exe users list
```
### Linux/Mac Example
```bash
OKTAORGURL=https://avensolutions.okta.com; OKTAAPITOKEN=xxxYOURTOKENHERExxx; ./okta-admin users list
```