# Name: PowerShell .NET Framework Checker
# By: Jason Savitt
# Version: 1.0
# Description: Displays the version of .NET framework that is installed on the local system.
# Syntax: .\dotnet_checker.ps1

# Iterates the registry .NET version information
$DotNetVer4 = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release
# Displays each version .NET 4.x and higher that is installed
Write-Output "The following version of .NET have been detected: "
if ($DotNetVer4 -ge 461808) {
	Write-Output "- .NET v4.7.2 or later"
	}
elseif ($DotNetVer4 -ge 461308) {
	Write-Output "- .NET v4.7.1"
	}
elseif ($DotNetVer4 -ge 460798) {
	Write-Output "- .NET v4.7"
	}
elseif ($DotNetVer4 -ge 394802) {
	Write-Output "- .NET v4.6.2"
	}
elseif ($DotNetVer4 -ge 394254) {
	Write-Output "- .NET v4.6.1"      
	}
elseif ($DotNetVer4 -ge 393295) {
	Write-Output "- .NET v4.6"      
	}
elseif ($DotNetVer4 -ge 379893) {
	Write-Output "- .NET v4.5.2"      
	}
elseif ($DotNetVer4 -ge 378675) {
	Write-Output "- .NET v4.5.1"      
	}
elseif ($DotNetVer4 -ge 378389) {
	Write-Output "- .NET v4.5"      
	}
else {
	Write-Output "Note: .NET version NOT Identified (.NET registry reference: " + $DotNetVer4 + ")"
	}

# Displays version .NET 3.5x if installed
if (Test-Path "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5\") {
	$DotNetVer35 = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5").Version
	Write-Output "- .NET Version: $DotNetVer35" 
	$DotNetVer35SP = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5").SP
	if ($DotNetVer35SP -ne '') {
		Write-Output "  - Service Pack: $DotNetVer35SP"
		} 
	}

# Displays version .NET 3.0x if installed
if (Test-Path "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.0\") {
	$DotNetVer30 = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.0").Version
	Write-Output "- .NET Version: $DotNetVer30" 
	$DotNetVer30SP = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.0").SP
	if ($DotNetVer30SP -ne '') {
		Write-Output "  - Service Pack: $DotNetVer30SP"
		} 
	}
