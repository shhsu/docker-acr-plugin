Param(
	[string]
	$targetDir = $pwd.Path,
	[string]
	$dockerRepo = "https://github.com/shhsu/docker.git",
	[string]
	$dockerBranch = "azure_login_v2",
	[string]
	$toolsRepo = "https://github.com/shhsu/docker-acr-plugin.git",
	[string]
	$toolsBranch = "no_challenge",
	[switch]
	$forceClean
)

function DeleteOutput($file) {
    $outputFile = Join-Path $targetDir $file
    if (Test-Path $outputFile) {
        Remove-Item $outputFile
    }
}

function Cleanup() {
	docker rm -f $buildContainer
	docker rmi -f $buildImage
	Remove-Item -Recurse -Force $workspace
}

if (!(Test-Path $targetDir)) {
	mkdir $targetDir
}

$ErrorActionPreference = "Stop"

$dockerOs = & "docker" "version" "--format" "'{{.Server.Os}}'"
if ($dockerOs.Trim() -ne "'windows'") {
    Write-Error "Please run ""%ProgramFiles%\Docker\Docker\DockerCli -SwitchDaemon"" to switch the daemon to windows"
}

$buildContainer = "acrloginbuild"
$buildImage = "acrloginbuildimg"
$workspace = Join-Path $env:TEMP "ACR_DOCKER_BUILD"
mkdir $workspace

if ($forceClean) {
	$ErrorActionPreference = "SilentlyContinue"
	Cleanup
	$ErrorActionPreference = "Stop"
}

DeleteOutput "docker-login-acr.exe"
DeleteOutput "docker.exe"

Push-Location $workspace
$ErrorActionPreference = "SilentlyContinue"
git clone $dockerRepo -b $dockerBranch docker 2>$null
$ErrorActionPreference = "Stop"

Push-Location docker
$DOCKER_GITCOMMIT=(git rev-parse --short HEAD)
docker build -t $buildImage -f Dockerfile.windows .
$windowsCaption = (Get-WmiObject -class Win32_OperatingSystem).Caption

$buildCmds =
	## build docker
	"hack\make.ps1 -Binary; " +
	## build tools
	"cd C:\go\src\github.com; " +
	"git clone $toolsRepo -b $toolsBranch docker-acr-plugin 2>`$null; " +
	"cd C:\go\src\github.com\docker-acr-plugin\docker-login-acr; " +
	"go build; " +
	"cd C:\go\src\github.com\docker-acr-plugin\login-config-editor;" +
	"go build";
if (!$windowsCaption.Contains("Windows Server")) {
	## hyper-v
	docker run --name $buildContainer -e DOCKER_GITCOMMIT=$DOCKER_GITCOMMIT -m 2GB $buildImage $buildCmds
} else {
	docker run --name $buildContainer -e DOCKER_GITCOMMIT=$DOCKER_GITCOMMIT $buildImage $buildCmds
}

Pop-Location
Pop-Location

docker cp ${buildContainer}:C:\go\src\github.com\docker\docker\bundles\docker.exe (Join-Path $targetDir "docker.exe")
docker cp ${buildContainer}:C:\go\src\github.com\docker\docker\bundles\dockerd.exe (Join-Path $targetDir "dockerd.exe")
docker cp ${buildContainer}:C:\go\src\github.com\docker-acr-plugin\docker-login-acr\docker-login-acr.exe (Join-Path $targetDir "docker-login-acr.exe")
docker cp ${buildContainer}:C:\go\src\github.com\docker-acr-plugin\login-config-editor\login-config-editor.exe (Join-Path $targetDir "login-config-editor.exe")
docker cp ${buildContainer}:C:\go\src\github.com\docker-acr-plugin\scripts\get.ps1 (Join-Path $targetDir "get.ps1")

$ErrorActionPreference = "Continue"
Cleanup
