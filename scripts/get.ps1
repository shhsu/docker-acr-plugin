param(
    [string]
    $installLocation,
    [string]
    $configFileLocation,
    [string]
    $blobSource = "https://aadacr.blob.core.windows.net/binaries/"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrEmpty($installLocation)) {
    $installLocation = Read-Host "Please provide a location to download your files. Or press enter to use the current directory"
    if ([string]::IsNullOrEmpty($installLocation)) {
        $installLocation = $pwd.Path
    } elseif (!(Test-Path $installLocation)) {
        mkdir $installLocation
        if (!(Test-Path $installLocation)) {
            Write-Error "Failed to created directory $installLocation"
        }
    }
    Write-Host "Files will be installed in $installLocation..."
}

if (!($blobSource.EndsWith("/"))) {
    $blobSource = $blobSource + "/"
}

ForEach  ($file in @("docker.exe", "dockerd.exe", "docker-login-acr.exe", "login-config-editor.exe")) {
    Invoke-WebRequest -Uri "${blobSource}${file}" -OutFile (Join-Path $installLocation $file)
}

if (![string]::IsNullOrEmpty($configFileLocation)) {
    $configFileOption = "--config-file $configFileLocation"
}

& (Join-Path $installLocation "login-config-editor.exe") --module "acr" --challenge-type "Bearer" --challenge-realm "https://*.azurecr.io/oauth2/token" $configFileOption
