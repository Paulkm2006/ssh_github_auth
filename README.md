## ssh-github-auth: Authenticate your SSH server using Github Organizations


This module implements PAM authentication to support interactive auth using Github device login.
You can allow users in a specific organization (and in a specific team) to access the SSH server, create an account for them and ask them whether to save their Github public keys into `authorized_keys` for further logins.

### Usage:
#### 1. Create a Github App at [here](https://github.com/settings/apps/new). Remember to check the `Enable Device Flow` option and grant the permission `Organization-Members-Read only`
#### 2. Install the Github App to your organization. You'll need to be a owner of the org or request permission from the owners to perform this.
#### 3. Download file `pam_ssh_github_auth.so` from Releases and move it into `/lib/security` (create the directory if not exist)
#### 4. Modify `/etc/pam.d/sshd`, comment out the line `@include common-auth`, and add the following line 
`auth required pam_ssh_github_auth.so client_id=xxx org=yyy team=zzz auto_create_user=sudoer allow_import_keys`

The parameters specifications are in this table
| param name | required | description |
|------------|----------|-------------|
| client_id | true | client_id for your Github App|
| org | true | Your organization's name |
| team | false | The team name of authorized users, split with `,` |
| auto_create_user | false | When specified with value `sudoer`, the program automatically add the user into sudoers file |
| allow_import_keys | false | Whether the users can choose to import their ssh keys into `authorized_keys` or not |

#### 5. Modify file `/etc/ssh/sshd_config`
Set `KbdInteractiveAuthentication yes` and `UsePAM yes`

#### 6. To automatically add users into sudoers, execute the following commands
```sh
# Run this as root
echo "sshd ALL=(ALL) NOPASSWD: /usr/sbin/useradd, /bin/mkdir, /bin/chmod, /bin/chown, /bin/mv, /usr/bin/visudo, /bin/bash -c echo*, /bin/cat, /bin/touch, /bin/rm" > /etc/sudoers.d/sshd_permissions
chmod 0440 /etc/sudoers.d/sshd_permissions
```

#### 7. Restart your sshd server