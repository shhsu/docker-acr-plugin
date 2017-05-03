Docker plugin, enable Azure Active Directory (AAD) scenario.

#Usage:

##### Build it

Run the installation script for [windows](install/install.ps1), or linux (WIP)

##### Edit config.json

Run the script for modifying your docker config on [windows] (install/azure_config.ps1), or linux (WIP)

##### Run it

######(Optional) Run dockerd
assuming your docker daemon is recent enough, the `docker.exe` we built should work with it already. Otherwise, run the dockerd that was just built
```
dockerd --run-service
```

###### AAD based device login-acr
```
docker login {myregistry}.azurecr.io
```
