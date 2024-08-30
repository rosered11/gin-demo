# Gin Demo


## Private Repo

### SSH

**.gitconfig**
```.gitconfig
[url "git@ssh.dev.azure.com:v3/myorg/myproj/myrepo"]
	insteadOf = https://dev.azure.com/myorg/myproj/myrepo
```
**command**

go get -u dev.azure.com/myorg/myproj/myrepo.git

## Public Repo

go get -u dev.azure.com/myorg/myproj/_git/myrepo.git