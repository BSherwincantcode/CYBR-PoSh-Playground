<###########################################################################

 NAME: AAM Password Change and Cache Update Demonstration Script

 AUTHOR: Brendan Sherwin

 COMMENT: 
 This script will display how an AAM Provider:
    - Cache update speed and capabilities
        - Object property modification
        - Application Authorization/Authentication changes
    - Race condition mitigation during a password change

 REQUIREMENTS:
 Windows host with AAM provider agent installed.  This script should be run locally on that host.

 SUPPORTED VERSIONS:
 CyberArk PVWA v12.1 and above
 

 VERSION HISTORY:
 1.0 	12/01/2023   	- Initial release
########################################################################### #>

param
(
    [Parameter(Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com/passwordvault)")]
    [Alias("url")]
    [String]$PVWAURL,

    [Parameter(Mandatory = $false, HelpMessage = "Enter the Authentication type (Default:CyberArk)")]
    [ValidateSet("cyberark", "ldap", "radius")]
    [String]$AuthType = "cyberark",

    [Parameter(Mandatory = $false, HelpMessage = "Enter the RADIUS OTP")]
    [ValidateScript({ $AuthType -eq "radius" })]
    [String]$OTP,

    [Parameter(Mandatory = $False, HelpMessage = "Enter the full path for the Provider CLI SDK:")]
    [String]$smSDKPath = "C:\Program Files (x86)\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe",
		
    [Parameter(Mandatory = $False, HelpMessage = "Enter the AppID")]
    [String]$AppID = "DemoApp1",

    [Parameter(Mandatory = $False, HelpMessage = "Enter the Safe Name")]
    [String]$SafeName = "SM_DemoSafe",

    [Parameter(Mandatory = $False, HelpMessage = "Enter the target account's address")]
    [String]$Address = "Domain.SecretsDemo.internal",

    [Parameter(Mandatory = $False, HelpMessage = "Enter the target account's username")]
    [String]$UserName = "ApplicationUser",
	
    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
    [Parameter(Mandatory = $False)]
    [Switch]$DisableSSLVerify
)

# ------ SET global parameters ------
# Set Log file path
$global:LOG_DATE = $(Get-Date -Format yyyyMMdd) + "-" + $(Get-Date -Format HHmmss)
$global:LOG_FILE_PATH = "$ScriptLocation\AAMDemo_$LOG_DATE.log"
# Set a global Header Token parameter
$global:g_LogonHeader = ""

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL + "/api"
$URL_Authentication = $URL_PVWAAPI + "/auth"
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + "/Logoff"

# URL Methods
# -----------
$URL_Safes = $URL_PVWAAPI + "/Safes"
$URL_SpecificSafe = $URL_Safes + "/{0}"
$URL_SafeMembers = $URL_SpecificSafe + "/Members"
$URL_SafeSpecificMember = $URL_SpecificSafe + "/Members/{1}"
$URL_SafeDetails = $URL_Safes + "/{0}"
$URL_Accounts = $URL_PVWAAPI + "/Accounts"
$URL_AccountsDetails = $URL_Accounts + "/{0}"
$URL_AccountsPassword = $URL_AccountsDetails + "/Password/Update"
$URL_PlatformDetails = $URL_PVWAAPI + "/Platforms/{0}"
$URL_Users = $URL_PVWAAPI + "/Users"

<#region Verify and update these values
#SDK Path
$smSDKPath = 'C:\Program Files (x86)\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe'

#Provider query variables
$AppID = 'TestApp1' #Enter the Application ID as listed in the Application page in the PVWA or via Users & Groups in the PrivateArk Client
$SafeName = 'P_HT_AAM_Safe' #Enter the safe name the target credential is stored in.  Ensure the provider user and application user ID have "List" and "Retrieve" access on the safe
$Address = 'ht.mtb' #Enter the address associated with the target credential
$UserName = 'SVC_AAMDemo' #Enter the username for the target credential

#endregion#>

#Modifying the output argument will break the table printing capability, please ensure to comment the line and create a new line rather than modifying the original
$OutputArg = 'PassProps.Username,PassProps.Address,PassProps.PolicyID,PasswordChangeInProcess,PassProps.StartChangeNotBefore,PassProps.OwnerEmail,Password'

#Do not modify the variables below
$data = @()
$time = 
$PassChangeInProcess = @()
$StartChangeNotBefore = @()

#$smParam = 'getpassword', '/p',"AppDescs.AppID=$AppID", "/p","Query=Safe=$SafeName;Address=$Address;UserName=$UserName", '/p','FailRequestOnPasswordChange=False','/o',"$OutputArg"

#region Functions


Function ConvertFrom-UnixTime() {
    <#
.SYNOPSIS
	Convert from UnixTime
.DESCRIPTION
	Convert from UnixTime
.PARAMETER time
    STR - Unix time passed into function
	
#>
    param(
        [Parameter(Mandatory = $true)]
        [String]$time
    )

    #check if null
    if ($time -eq "<na>"){
        return "<na>"
    }
    else{

        $changeDate = (Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds([INT]$time - 14400))

        return $changeDate
    }

}

Function Get-Secret() {
    <#
.SYNOPSIS
	Retrieve a secret
.DESCRIPTION
	Issues a command to the Secrets Manager CLI SDK to retrieve a secret as well as any additional properties required
.PARAMETER AppID
	The Application ID, as defined in the CyberArk environment
.PARAMETER SafeName
    The name of the safe that houses the target account
.PARAMETER Address
    The Address for the target account, as defined within the CyberArk environment
.PARAMETER UserName
    The username for the target account, as defined within the CyberArk environment
.PARAMETER OutputArg
    The properties requested as output from the request to the Provider (along with the secret)
.PARAMETER FailonChange
    Determines whether a request will fail if made while a password is being rotated rather than returning a PasswordChangeInProcess flag.  Defaults to False
#>

    param(
        [Parameter(Mandatory = $true)]
        [String]$AppID,
        [Parameter(Mandatory = $true)]
        [String]$SafeName,
        [Parameter(Mandatory = $true)]
        [String]$Address,
        [Parameter(Mandatory = $true)]
        [String]$UserName,
        [Parameter(Mandatory = $true)]
        [String]$OutputArg,
        [Parameter(Mandatory = $False)]
        [Bool]$FailonChange = $False
    )


    try{
        $oldPreference = $ErrorActionPreference
        $ErrorActionPreference = 'stop'
        
        Get-ChildItem $smSDKPath
        
        $smParam = 'getpassword', '/p',"AppDescs.AppID=$AppID", "/p","Query=Safe=$SafeName;Address=$Address;UserName=$UserName", '/p',"FailRequestOnPasswordChange=$FailonChange",'/o',"$OutputArg"

        Write-LogMessage -type Debug -Header "Call made to provider:" -MSG "$smSDKPath $smParam"
        $output = & $smSDKPath $smParam
        Write-LogMessage -type Debug -Header "Return from Provider:" -MSG "$output"
        
        $output = $output.split(',')

        return $output
                      
    }
    Catch [System.IO.FileNotFoundException],[System.IO.DirectoryNotFoundException]{
        Write-LogMessage -type Error -header "Selected path not found for Provider EXE or Provider SDK" -MSG "Could not find file: $PSItem.Exception.FileName"
    }
    Catch{   
        Write-LogMessage -type Error -Header "Issue retrieving secret" -MSG "$_"
        
    }
    Finally{
        $ErrorActionPreference = $oldPreference
    }
}


Function Test-CommandExists {
    <#
.SYNOPSIS
	Test if a Powershell command exists
.DESCRIPTION
	Determines if a powershell command is available for use
.PARAMETER command
	The command to test
#>
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {
        if (Get-Command $command) {
            RETURN $true
        }
    }
    Catch {
        Write-LogMessage -type Error "Powershell command $command does not exist"; RETURN $false
    }
    Finally {
        $ErrorActionPreference = $oldPreference
    }
} #end function test-CommandExists

Function ConvertTo-URL($sText) {
    <#
.SYNOPSIS
	HTTP Encode test in URL
.DESCRIPTION
	HTTP Encode test in URL
.PARAMETER sText
	The text to encode
#>
    if ($sText.Trim() -ne "") {
        Write-LogMessage -Type Debug -Msg "Returning URL Encode of $sText"
        return [URI]::EscapeDataString($sText)
    }
    else {
        return $sText
    }
}
Function Write-LogMessage {
    <#
.SYNOPSIS
	Method to log a message on screen and in a log file

.DESCRIPTION
	Logging The input Message to the Screen and the Log File.
	The Message Type is presented in colours on the screen based on the type

.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose")]
        [String]$type = "Info",
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH
    )
    try {
        If ($Header) {
            "=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
            Write-Host "======================================="
        }
        ElseIf ($SubHeader) { 
            "------------------------------------" | Out-File -Append -FilePath $LOG_FILE_PATH 
            Write-Host "------------------------------------"
        }
	
        $msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
        $writeToFile = $true
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) {
            $Msg = "N/A" 
        }
        # Mask Passwords
        if ($Msg -match '((?:"password"|"secret"|"NewCredentials")\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w!@#$%^&*()-\\\/]+))') {
            $Msg = $Msg.Replace($Matches[2], "****")
        }
        # Check the message type
        switch ($type) {
            "Info" { 
                Write-Host $MSG.ToString()
                $msgToWrite += "[INFO]`t$Msg"
            }
            "Warning" {
                Write-Host $MSG.ToString() -ForegroundColor DarkYellow
                $msgToWrite += "[WARNING]`t$Msg"
            }
            "Error" {
                Write-Host $MSG.ToString() -ForegroundColor Red
                $msgToWrite += "[ERROR]`t$Msg"
            }
            "Debug" { 
                if ($InDebug -or $InVerbose) {
                    Write-Debug $MSG
                    $msgToWrite += "[DEBUG]`t$Msg"
                }
                else {
                    $writeToFile = $False 
                }
            }
            "Verbose" { 
                if ($InVerbose) {
                    Write-Verbose $MSG
                    $msgToWrite += "[VERBOSE]`t$Msg"
                }
                else {
                    $writeToFile = $False 
                }
            }
        }
		
        If ($writeToFile) {
            $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH 
        }
        If ($Footer) { 
            "=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
            Write-Host "======================================="
        }
    }
    catch {
        Write-Error "Error in writing log: $($_.Exception.Message)" 
    }
}

Function Join-ExceptionMessage {
    <#
.SYNOPSIS
	Formats exception messages
.DESCRIPTION
	Formats exception messages
.PARAMETER Exception
	The Exception object to format
#>
    param(
        [Exception]$e
    )

    Begin {
    }
    Process {
        $msg = "Source:{0}; Message: {1}" -f $e.Source, $e.Message
        while ($e.InnerException) {
            $e = $e.InnerException
            $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
        }
        return $msg
    }
    End {
    }
}

Function Get-LogonHeader {
    <# 
.SYNOPSIS 
	Get-LogonHeader
.DESCRIPTION
	Get-LogonHeader
.PARAMETER Credentials
	The REST API Credentials to authenticate
#>
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CredentialAttribute()]$Credentials,
        [Parameter(Mandatory = $false)]
        [string]$RadiusOTP,
        [Parameter(Mandatory = $false)]
        [boolean]$concurrentSession
    )
	
    if ([string]::IsNullOrEmpty($g_LogonHeader)) {
        # Disable SSL Verification to contact PVWA
        If ($DisableSSLVerify) {
            Disable-SSLVerification
        }
		
        # Create the POST Body for the Logon
        # ----------------------------------
        If ($concurrentSession) {
            $logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; concurrentSession = $true } | ConvertTo-Json
        }
        else {
            $logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password } | ConvertTo-Json

        }
        # Check if we need to add RADIUS OTP
        If (![string]::IsNullOrEmpty($RadiusOTP)) {
            $logonBody.Password += ",$RadiusOTP"
        } 
        try {
            # Logon
            $logonToken = Invoke-RestMethod -Method Post -Uri $URL_Logon -Body $logonBody -ContentType "application/json" -TimeoutSec 2700
			
            # Clear logon body
            $logonBody = ""
        }
        catch {
            Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)", $_.Exception))
        }

        $logonHeader = $null
        If ([string]::IsNullOrEmpty($logonToken)) {
            Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
        }
		
        try {
            # Create a Logon Token Header (This will be used through out all the script)
            # ---------------------------
            $logonHeader = @{Authorization = $logonToken }

            Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global		
        }
        catch {
            Throw $(New-Object System.Exception ("Get-LogonHeader: Could not create Logon Headers Dictionary", $_.Exception))
        }
    }
}

Function Invoke-Logoff {
    <# 
.SYNOPSIS 
	Invoke-Logoff
.DESCRIPTION
	Logoff a PVWA session
#>
    try {
        # Logoff the session
        # ------------------
        If ($null -ne $g_LogonHeader) {
            Write-LogMessage -Type Info -Msg "Logoff Session..."
            Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 | Out-Null
            Set-Variable -Name g_LogonHeader -Value $null -Scope global
        }
    }
    catch {
        Throw $(New-Object System.Exception ("Invoke-Logoff: Failed to logoff session", $_.Exception))
    }
}

Function Disable-SSLVerification {
    <# 
.SYNOPSIS 
	Bypass SSL certificate validations
.DESCRIPTION
	Disables the SSL Verification (bypass self signed SSL certificates)
#>
    # Check if to disable SSL verification
    If ($DisableSSLVerify) {
        try {
            Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
            # Using Proxy Default credentials if the Server needs Proxy credentials
            [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            # Using TLS 1.2 as security protocol verification
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            # Disable SSL Verification
            if (-not("DisableCertValidationCallback" -as [type])) {
                Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class DisableCertValidationCallback {
    public static bool ReturnTrue(object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }

    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(DisableCertValidationCallback.ReturnTrue);
    }
}
"@ 
            }

            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [DisableCertValidationCallback]::GetDelegate()
        }
        catch {
            Write-LogMessage -Type Error -Msg "Could not change SSL validation. Error: $(Join-ExceptionMessage $_.Exception)"
        }
    }
    Else {
        try {
            Write-LogMessage -Type Info -Msg "Setting script to use TLS 1.2"
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        catch {
            Write-LogMessage -Type Error -Msg "Could not change SSL setting to use TLS 1.2. Error: $(Join-ExceptionMessage $_.Exception)"
        }
    }
}

Function List-MainMenu {
    <# 
.SYNOPSIS 
	Behavioral Menu
.DESCRIPTION
	List of options a user can select, initiating a demonstration of the behavior
#>
    
    Clear-Host
    Write-Host "============== Provider Demonstration =============="

    Write-Host "1: Cached Password Property Update"
    Write-Host "2: Cached Password Authentication Update"
    Write-Host "3: Secret Rotation Process"
    Write-Host "4: Create Environment with Default Values"
    #Write-Host "5: Update Values"
    Write-Host "Q: Quit"
}

Function List-ValuesMenu{
<# 
.SYNOPSIS 
	Variables Menu
.DESCRIPTION
	Allows user to update varibles
#>

    Clear-Host
    Write-Host "-------------- Update Values --------------"

    Write-Host "1: AppID - $AppID"
    Write-Host "2: Safename - $SafeName"
    Write-Host "3: Address - $Address"
    Write-Host "4: Username - $Username"
    Write-Host "5: FailOnChangeFlag - $FailOnChange"
    Write-Host "B: Back"
    
}

Function Update-Property{

}

Function Update-AppAuthentication{

}

Function Rotate-Credential{

}

Function Refresh-Cache{

}

Function Get-ProviderUser{

}

Function Create-Enviroment{
<# 
.SYNOPSIS 
	Creates data necessary for provider demonstration
.DESCRIPTION
    Will create a Safe, Application ID, and password object.
    The user running the script, the local provider, the ApplicationUserID, and the VaultAdmins group are granted authorizations on the safe.
.PARAMETER AppUserID
    The ID of the application user that will be created in the environment
.PARAMETER SafeName
    The name of the safe created for testing
.PARAMETER ObjectUserName
    The UserName for the secret that will be created in the environment
.PARAMETER ObjectAddress
    The address for the secret that will be created in the environment
.PARAMETER fakeEmail
    The fake email address that will be attached to the created object
#>

    param(
        [Parameter(Mandatory = $true)]
        [String]$appUserID,
        [Parameter(Mandatory = $true)]
        [String]$SafeName,
        [Parameter(Mandatory = $true)]
        [String]$ObjectUsername,
        [Parameter(Mandatory = $true)]
        [String]$ObjectAddress,
        [Parameter(Mandatory = $true)]
        [String]$fakeEmail = "Not_A_Real_Email@fake.place"
    )

    
    
    Get-LogonHeader

    #Test to see if user exists
    if((Get-AppUser $appUserID) -ne $null){
        Write-LogMessage -type Warning -MSG "Application ID $appUserID already exists"
    }
    Else{
        New-AppUser $appUserID
    }

    if(Test-Safe -safeName $safeName -eq $False){
        Try{
            New-Safe -safename $safeName -numVersionRetention 1 -managingCPM "PasswordManager"
            Set-SafeMember -safename $safeName -updateMember -safeMember "Vault Admins" -memberSearchInLocation Vault -permUseAccounts -permRetrieveAccounts -permListAccounts -permAddAccounts -permUpdateAccountContent -permUpdateAccountProperties -permInitiateCPMManagement -permSpecifyNextAccountContent -permRenameAccounts -permDeleteAccounts -permUnlockAccounts -permManageSafe -permManageSafeMembers -permBackupSafe -permViewAuditLog -permViewSafeMembers -permRequestsAuthorizationLevel -permAccessWithoutConfirmation -permCreateFolders -permDeleteFolders -permMoveAccountsAndFolders
            Set-SafeMember -safename $safeName -updateMember -SafeMember (Get-ProviderUser) -memberSearchInLocation Vault -permUseAccounts -permListAccounts
            }
        Catch{
            Write-LogMessage -type Error -MSG "Error creating Demo Safe"
        }
    }
    

}

Function Test-Safe {
    <# 
.SYNOPSIS 
	Returns the Safe members
.DESCRIPTION
	Returns the Safe members
.PARAMETER SafeName
	The Safe Name check if exists
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [String]$safeName
    )
		
        try {
                $chkSafeExists = $null -ne $(Get-Safe -safeName $safeName -ErrAction "SilentlyContinue")
        }
       catch {
           $chkSafeExists = $false
        }
		
        # Report on safe existence
        If ($chkSafeExists -eq $true) {
            # Safe exists
            Write-LogMessage -Type Info -MSG "Safe $safeName exists"
            $retResult = $true
        }
        Else {
            # Safe does not exist
            Write-LogMessage -Type Warning -MSG "Safe $safeName does not exist"
            $retResult = $false
        }
    
    return $retResult
}

Function New-Safe {
    <#
.SYNOPSIS
Allows a user to create a new cyberArk safe

.DESCRIPTION
Creates a new cyberark safe

.EXAMPLE
New-Safe -safename "x0-Win-S-Admins" -safeDescription "Safe description goes here"

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$safename,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$safeDescription,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$managingCPM,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]$numVersionRetention = 7,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]$numDaysRetention = -1,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [bool]$EnableOLAC = $false
    )

    $createSafeBody = @{
        "SafeName"                  = "$safename"; 
        "Description"               = "$safeDescription"; 
        "OLACEnabled"               = $enableOLAC; 
        "ManagingCPM"               = "$managingCPM";
        "NumberOfVersionsRetention" = $numVersionRetention;
    }

    If ($numDaysRetention -gt -1) {
        $createSafeBody.Add("NumberOfDaysRetention", $numDaysRetention)
        $createSafeBody.Remove("NumberOfVersionsRetention")
    }

    try {
        Write-LogMessage -Type Debug -Msg "Adding the safe $safename to the Vault..."
        $safeAdd = Invoke-RestMethod -Uri $URL_Safes -Body ($createSafeBody | ConvertTo-Json) -Method POST -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700
        # Reset cached Safes list
        #Set-Variable -Name g_SafesList -Value $null -Scope Global
        # Update Safes list to include new safe
        #Get-Safes | out-null
        $g_SafesList += $safeAdd
    }
    catch {
        Throw $(New-Object System.Exception ("New-Safe: Error adding $safename to the Vault.", $_.Exception))
    }
}

Function Update-Safe {
    <#
.SYNOPSIS
Allows a user to update an existing cyberArk safe

.DESCRIPTION
Updates a new cyberark safe

.EXAMPLE
Update-Safe -safename "x0-Win-S-Admins" -safeDescription "Updated Safe description goes here" -managingCPM "PassManagerDMZ"

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$safeName,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$safeDescription,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$managingCPM,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]$numVersionRetention = -1,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]$numDaysRetention = -1,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [bool]$EnableOLAC
    )
    try {
        # Get the current safe details and update when necessary
        $getSafe = Get-Safe -safeName $safeName
    }
    catch {
        Throw $(New-Object System.Exception ("Update-Safe: Error getting current details on safe '$safeName'", $_.Exception))
    }
    $updateDescription = $getSafe.Description
    $updateOLAC = $getSafe.OLACEnabled
    $updateManageCPM = $getSafe.ManagingCPM
    $updateRetVersions = $getSafe.NumberOfVersionsRetention
    $updateRetDays = $getSafe.NumberOfDaysRetention
	
    If (![string]::IsNullOrEmpty($safeDescription) -and $getSafe.Description -ne $safeDescription) {
        $updateDescription = $safeDescription
    }
    If ($getSafe.OLACEnabled -ne $EnableOLAC) {
        $updateOLAC = $EnableOLAC
    }
    If (![string]::IsNullOrEmpty($managingCPM) -and $getSafe.ManagingCPM -ne $managingCPM) {
        If ("NULL" -eq $managingCPM) {
            $updateManageCPM = ""
        }
        else {
            $updateManageCPM = $managingCPM
        }
    }
    If ($null -ne $numVersionRetention -and $numVersionRetention -gt 0 -and $getSafe.NumberOfVersionsRetention -ne $numVersionRetention) {
        $updateRetVersions = $numVersionRetention
    }
    If ($null -ne $numDaysRetention -and $numDaysRetention -gt 0 -and $getSafe.NumberOfDaysRetention -ne $numDaysRetention) {
        $updateRetDays = $numDaysRetention
    }
	
    $updateSafeBody = @{
        "SafeName"                  = "$safeName"; 
        "Description"               = "$updateDescription"; 
        "OLACEnabled"               = $updateOLAC; 
        "ManagingCPM"               = "$updateManageCPM";
        "NumberOfVersionsRetention" = $updateRetVersions;
        "NumberOfDaysRetention"     = $updateRetDays;
    } | ConvertTo-Json

    try {
        Write-LogMessage -Type Debug -Msg "Updating safe $safename..."
        Write-LogMessage -Type Debug -Msg "Update Safe Body: $updateSafeBody" 
        $null = Invoke-RestMethod -Uri ($URL_SpecificSafe -f $safeName) -Body $updateSafeBody -Method PUT -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700
    }
    catch {
        Throw $(New-Object System.Exception ("Update-Safe: Error updating $safeName.", $_.Exception))
    }
}

Function Remove-Safe {
    <#
.SYNOPSIS
Allows a user to delete a cyberArk safe

.DESCRIPTION
Deletes a cyberark safe

.EXAMPLE
Remove-Safe -safename "x0-Win-S-Admins"

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$safename
    )

    try {
        Write-LogMessage -Type Debug -Msg "Deleting the safe $safename from the Vault..."
        $null = Invoke-RestMethod -Uri ($URL_SpecificSafe -f $safeName) -Method DELETE -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700
    }
    catch {
        Throw $(New-Object System.Exception ("Remove-Safe: Error deleting $safename from the Vault.", $_.Exception))
    }
}

Function Set-SafeMember {
    <#
.SYNOPSIS
Gives granular permissions to a member on a cyberark safe

.DESCRIPTION
Gives granular permission to a cyberArk safe to the particular member based on parameters sent to the command.

.EXAMPLE
Set-SafeMember -safename "Win-Local-Admins" -safeMember "Win-Local-Admins" -memberSearchInLocation "LDAP Directory Name"

.EXAMPLE
Set-SafeMember -safename "Win-Local-Admins" -safeMember "Administrator" -memberSearchInLocation vault

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateScript( { Test-Safe -SafeName $_ })]
        $safename,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        $safeMember,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [switch]$updateMember,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [switch]$deleteMember,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Which vault-integrated LDAP directory name the vault should search for the account. Must match one of the directory names defined in the LDAP Integration page of the PVWA.",
            Position = 0)]
        $memberSearchInLocation = "Vault",
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        #[ValidateSet("User","Group","Role")]
        [String]$memberType="User",
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permUseAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permRetrieveAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permListAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permAddAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permUpdateAccountContent = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permUpdateAccountProperties = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permInitiateCPMManagement = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permSpecifyNextAccountContent = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permRenameAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permDeleteAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permUnlockAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permManageSafe = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permManageSafeMembers = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permBackupSafe = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permViewAuditLog = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permViewSafeMembers = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [int]$permRequestsAuthorizationLevel = 0,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permAccessWithoutConfirmation = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permCreateFolders = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permDeleteFolders = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permMoveAccountsAndFolders = $false
    )

    If ($safeMember -NotIn $g_DefaultUsers) {
        Write-LogMessage -type Debug -MSG "Member Type: $memberType"
        Write-LogMessage -type Debug -MSG "SafeMember var: $safeMember"
        $SafeMembersBody = @{
            MemberName               = "$safeMember"
            SearchIn                 = "$memberSearchInLocation"
            MembershipExpirationDate = "$null"
            MemberType               = "$memberType"
            Permissions              = @{
                useAccounts                            = $permUseAccounts
                retrieveAccounts                       = $permRetrieveAccounts
                listAccounts                           = $permListAccounts
                addAccounts                            = $permAddAccounts
                updateAccountContent                   = $permUpdateAccountContent
                updateAccountProperties                = $permUpdateAccountProperties
                initiateCPMAccountManagementOperations = $permInitiateCPMManagement
                specifyNextAccountContent              = $permSpecifyNextAccountContent 
                renameAccounts                         = $permRenameAccounts
                deleteAccounts                         = $permDeleteAccounts
                unlockAccounts                         = $permUnlockAccounts
                manageSafe                             = $permManageSafe
                manageSafeMembers                      = $permManageSafeMembers
                backupSafe                             = $permBackupSafe
                viewAuditLog                           = $permViewAuditLog
                viewSafeMembers                        = $permViewSafeMembers
                accessWithoutConfirmation              = $permAccessWithoutConfirmation
                createFolders                          = $permCreateFolders
                deleteFolders                          = $permDeleteFolders
                moveAccountsAndFolders                 = $permMoveAccountsAndFolders
                requestsAuthorizationLevel1            = ($permRequestsAuthorizationLevel -eq 1)
                requestsAuthorizationLevel2            = ($permRequestsAuthorizationLevel -eq 2)
            }
        }  
    
        try {
            If ($updateMember) {
                Write-LogMessage -Type Debug -Msg "Updating safe membership for $safeMember on $safeName in the vault..."
                $urlSafeMembers = ($URL_SafeSpecificMember -f $(ConvertTo-URL $safeName), $safeMember)
                $restMethod = "PUT"
            }
            elseif ($deleteMember) {
                Write-LogMessage -Type Debug -Msg "Deleting $safeMember from $safeName in the vault..."
                $urlSafeMembers = ($URL_SafeSpecificMember -f $(ConvertTo-URL $safeName), $safeMember)
                $restMethod = "DELETE"
            }
            else {
                # Adding a member
                Write-LogMessage -Type Debug -Msg "Adding $safeMember located in $memberSearchInLocation to $safeName in the vault..."
                $urlSafeMembers = ($URL_SafeMembers -f $(ConvertTo-URL $safeName))
                $restMethod = "POST"
            }
            $null = Invoke-RestMethod -Uri $urlSafeMembers -Body ($safeMembersBody | ConvertTo-Json -Depth 5) -Method $restMethod -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 -ErrorVariable rMethodErr
        }
        catch {
            if ($rMethodErr.message -like "*User or Group is already a member*") {
                Write-LogMessage -Type Warning -Msg "The user $safeMember is already a member. Use the update member method instead"
            }
            elseif (($rMethodErr.message -like "*User or Group was not found.*") -or ($rMethodErr.message -like "*404*")) {   

                If ($AddOnUpdate) {
                    # Adding a member
                    Write-LogMessage -Type Warning -Msg "User or Group was not found. Attempting to adding $safeMember located in $memberSearchInLocation to $safeName in the vault..."
                    $urlSafeMembers = ($URL_SafeMembers -f $(ConvertTo-URL $safeName))
                    $restMethod = "POST"
                    try {
                        $null = Invoke-RestMethod -Uri $urlSafeMembers -Body ($safeMembersBody | ConvertTo-Json -Depth 5) -Method $restMethod -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 -ErrorVariable rMethodErr
                    }
                    catch {

                        Write-LogMessage -Type Error -Msg "There was an error setting the membership for $safeMember on $safeName in the Vault. The error was:"
                        Write-LogMessage -Type Error -Msg ("{0} ({1})" -f $rMethodErr.message, $_.Exception.Response.StatusDescription)
                    }
                }
                else {
                    Write-LogMessage -Type Warning -Msg "User or Group was not found. To automatically attempt to add use AddOnUpdate"
                }
            }
            else {
                Write-LogMessage -Type Error -Msg "There was an error setting the membership for $safeMember on $safeName in the Vault. The error was:"
                Write-LogMessage -Type Error -Msg ("{0} ({1})" -f $rMethodErr.message, $_.Exception.Response.StatusDescription)
            }
        }
    }
    else {
        Write-LogMessage -Type Info -Msg "Skipping default user $safeMember..."
    }
}

Function Get-SafeMembers {
    <#
.SYNOPSIS
Returns the permissions of a member on a cyberark safe

.DESCRIPTION
Returns the permissions of a cyberArk safe of all members based on parameters sent to the command.

.EXAMPLE
Get-SafeMember -safename "Win-Local-Admins" 

#> 
    param (
        [Parameter(Mandatory = $true)]
        [String]$safeName
    )
    $_safeMembers = $null
    $_safeOwners = $null
    try {
        $accSafeMembersURL = $URL_SafeMembers -f $(ConvertTo-URL $safeName)
        $_safeMembers = $(Invoke-RestMethod -Uri $accSafeMembersURL -Method GET -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 -ErrorAction "SilentlyContinue")
        # Remove default users and change UserName to MemberName
        $_safeOwners = $_safeMembers.value | Where-Object { $_.MemberName -NotIn $g_DefaultUsers }
    }
    catch {
        Throw $(New-Object System.Exception ("Get-SafeMembers: There was an error getting the safe $safeName Members.", $_.Exception))
    }
	
    return $_safeOwners
}

Function New-AccountObject {
	<# 
.SYNOPSIS 
	Creates a new Account Object
.DESCRIPTION
	Creates a new Account Object
.PARAMETER AccountLine
	(Optional) Account Object Name
#>
	param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()] 
		[PSObject]$AccountLine
	)
	try {
		# Set the Account Log name for further logging and troubleshooting
		$logFormat = ""
		If (([string]::IsNullOrEmpty($AccountLine.userName) -or [string]::IsNullOrEmpty($AccountLine.Address)) -and (![string]::IsNullOrEmpty($AccountLine.name))) {
			$logFormat = (Get-TrimmedString $AccountLine.name)
		}
		Else {
			$logFormat = ("{0}@{1}" -f $(Get-TrimmedString $AccountLine.userName), $(Get-TrimmedString $AccountLine.address))
		}
		Set-Variable -Scope Global -Name g_LogAccountName -Value $logFormat

		# Check mandatory fields
		If ([string]::IsNullOrEmpty($AccountLine.safe)) {
			throw "Missing mandatory field: Safe Name" 
  }
		if ($Create) {
			# Check mandatory fields for account creation
			If ([string]::IsNullOrEmpty($AccountLine.userName)) {
				throw "Missing mandatory field: user Name" 
   }
			If ([string]::IsNullOrEmpty($AccountLine.address)) {
				throw "Missing mandatory field: Address" 
   }
			If ([string]::IsNullOrEmpty($AccountLine.platformId)) {
				throw "Missing mandatory field: Platform ID" 
   }
		}
		
		# Check if there are custom properties
		$excludedProperties = @("name", "username", "address", "safe", "platformid", "password", "key", "enableautomgmt", "manualmgmtreason", "groupname", "groupplatformid", "remotemachineaddresses", "restrictmachineaccesstolist", "sshkey")
		$customProps = $($AccountLine.PSObject.Properties | Where-Object { $_.Name.ToLower() -NotIn $excludedProperties })
		#region [Account object mapping]
		# Convert Account from CSV to Account Object (properties mapping)
		$_Account = "" | Select-Object "name", "address", "userName", "platformId", "safeName", "secretType", "secret", "platformAccountProperties", "secretManagement", "remoteMachinesAccess"
		$_Account.platformAccountProperties = $null
		$_Account.secretManagement = "" | Select-Object "automaticManagementEnabled", "manualManagementReason"
		$_Account.name = (Get-TrimmedString $AccountLine.name)
		$_Account.address = (Get-TrimmedString $AccountLine.address)
		$_Account.userName = (Get-TrimmedString $AccountLine.userName)
		$_Account.platformId = (Get-TrimmedString $AccountLine.platformID)
		$_Account.safeName = (Get-TrimmedString $AccountLine.safe)
		if ((![string]::IsNullOrEmpty($AccountLine.password)) -and ([string]::IsNullOrEmpty($AccountLine.SSHKey))) { 
			$_Account.secretType = "password"
			$_Account.secret = $AccountLine.password
		}
		elseif (![string]::IsNullOrEmpty($AccountLine.SSHKey)) { 
			$_Account.secretType = "key" 
			$_Account.secret = $AccountLine.SSHKey
		}
		else {
			# Empty password
			$_Account.secretType = "password"
			$_Account.secret = $AccountLine.password
		}
		if (![string]::IsNullOrEmpty($customProps)) {
			# Convert any non-default property in the CSV as a new platform account property
			if ($null -eq $_Account.platformAccountProperties) {
				$_Account.platformAccountProperties = New-Object PSObject 
   }
			For ($i = 0; $i -lt $customProps.count; $i++) {
				$prop = $customProps[$i]
				If (![string]::IsNullOrEmpty($prop.Value)) {
					$_Account.platformAccountProperties | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $prop.Value 
				}
			}
		}
		If (![String]::IsNullOrEmpty($AccountLine.enableAutoMgmt)) {
			$_Account.secretManagement.automaticManagementEnabled = Convert-ToBool $AccountLine.enableAutoMgmt
			if ($_Account.secretManagement.automaticManagementEnabled -eq $false) {
				$_Account.secretManagement.manualManagementReason = $AccountLine.manualMgmtReason 
   }
		}
		if ($AccountLine.PSobject.Properties.Name -contains "remoteMachineAddresses") {
			if ($null -eq $_Account.remoteMachinesAccess) {
				$_Account.remoteMachinesAccess = New-Object PSObject 
   }
			$_Account.remoteMachinesAccess | Add-Member -MemberType NoteProperty -Name "remoteMachines" -Value $AccountLine.remoteMachineAddresses
		}
		if ($AccountLine.PSobject.Properties.Name -contains "restrictMachineAccessToList") {
			if ($null -eq $_Account.remoteMachinesAccess) {
				$_Account.remoteMachinesAccess = New-Object PSObject 
   }
			$_Account.remoteMachinesAccess | Add-Member -MemberType NoteProperty -Name "accessRestrictedToRemoteMachines" -Value $AccountLine.restrictMachineAccessToList
		}
		#endregion [Account object mapping]
				
		return $_Account
	}
 catch {
		Throw $(New-Object System.Exception ("New-AccountObject: There was an error creating a new account object.", $_.Exception))
	}
}

Function Get-AppUser{
    <# 
.SYNOPSIS 
	Determins if an Application ID exists
.DESCRIPTION
	Searches for user, returns compatible Application User information
.PARAMETER appUserID
	UserName is the user being searched for
#>
    param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()] 
    [String]$appuserID
    )
    Write-LogMessage -type Info -MSG "Looking for User $userID"

    $users = $null

    Try{
        $searchUserURL = $PVWAURL + ("/WebServices/PIMServices.svc/Applications/$(ConvertTo-URL $appUserID)")
        Write-LogMessage -type Verbose -MSG ("Application UserID search URL: ",$searchUserURL)
        $Users = $(Invoke-RestMethod -Uri $searchUserURL -Method GET -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 -ErrorAction "SilentlyContinue")
        Write-LogMessage -type Verbose -Header "Results from user search for AppUserID $appUserID" -MSG $($users | Select-Object -ExpandProperty Application | Select-Object -Property AppID)

        return $users

    }
    Catch{
        Write-LogMessage -type Error -Header "Unable to find user: $UserID" -MSG ("Error Info: ",$_.Exception)
    }
    

}

Function New-AppUser{
<# 
.SYNOPSIS 
	Creates a new ApplicationUser
.DESCRIPTION
	Creates a new ApplicationUser
.PARAMETER appUserID
	The ID for the new User
#>

    param(
        [Parameter(Mandatory = $true)]
        [String]$appUserID
        )

    try{
        
        $tempBody = @{
            "AppID"                     = "$appUserID"; 
            "Description"               = "AppID for Secrets Manager demo"; 
            "Location"                  = "\";
        }

        $newAppuserBody = @{
            "application"              = $tempBody
            } | ConvertTo-JSON

        $newAppUserURL = $PVWAURL + "/WebServices/PIMServices.svc/Applications/"
        Write-LogMessage -type Verbose -MSG "URL for adding Application User: $newAppUserURL"
        $null = Invoke-RestMethod -Uri ($newAppUserURL) -Body $newAppUserBody -Method Post -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700
    }
    Catch{
        Write-LogMessage -type Error -Header "There was an error creating the Application User" -MSG "$_.Exception"
    }
    try{
        Write-LogMessage -type Info -MSG "Adding Authentication Rule (Source IP) to Application $appUserID"

        

        Get-HostIP | %{
            $hostIP = $_.IPAddress

        }




    }
    Catch{

    }
}

Function Update-AppAuth{
<# 
.SYNOPSIS 
	Updates AppID Authentication rules
.DESCRIPTION
	Updates AppID Authentication rules, allowing for modifying existing rules or creating new ones, currently limited to IP/Hostnames only
.PARAMETER appID
    The ID of the application the rules will be modified for
.PARAMETER address
    The address added to the authorization rule
#>
        

        $tempBody = @{
        "AuthType"                     = "machineAddress"; 
        "AuthValue"                    = "$address"; 
        
        }

        $appAuthBody = @{
            "authentication"              = $tempBody
            } | ConvertTo-JSON 

        $appAuthURL = $PVWAURL + "/WebServices/PIMServices.svc/Applications/$appID/Authentications"
        Write-LogMessage -type Verbose -MSG "URL for adding MachineAddress ($address) authentication rule for Application: $newAppUserURL"
        $null = Invoke-RestMethod -Uri  $appAuthURL -Body $appAuthBody -Method Post -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700
}

Function Get-HostIP{
<# 
.SYNOPSIS 
	Gets Host IPs
.DESCRIPTION
	Returns non-Localhost IPv4 addresses for host
#>
    $hostIP = get-netipaddress | ?{$_.AddressFamily -eq "IPv4" -and $_.InterfaceAlias -notLike "Loopback*"}

    return $hostIP
}

<#Function View-ValueMenu{
    do{
        List-ValueMenu
        $option = Read-Host "Select a value to update"
        switch ($option){
            '1' { Update-Value($AppID) }
            '2' { Update-Value($SafeName) }
            '3' { Update-Value($Address) }
            '4' { Update-Value($Username) }
            '5' { Update-Value($FailOnChange) }
        }

}


Function Update-Value{

}#>
#endregion

do{
    List-MainMenu
    $option = Read-Host "Select a demonstration:"
    switch ($option){
        '1' { Update-Property }
        '2' { Update-AppAuthentication }
        '3' { Rotate-Credential }
        '4' { Create-Env }
        #'5' { Update-Value }
    }
    pause
}
until ($option.ToLower() -eq 'q')

#Initial retrieval of data


& $smSDKPath $smParam | %{$initial = $_}

$initial = $initial.split(",")
$pull = $initial
$pass = $initial[6]

$data = $data += @{Time=(get-date -Format "HH:mm:ss");Username=$pull[0];Address=$pull[1];Safe=$pull[2];PasswordChangeInProcess=$pull[3];StartChangeNotBefore=ConvertFrom-UnixTime($pull[4]);UserEmail=$pull[5];Password=$pull[6]}
$data | %{[PSCustomObject]$_} | Format-Table -AutoSize -Property Time,Password,Username,Address,Safe,UserEmail,PasswordChangeInProcess,StartChangeNotBefore


$save = @()

while ($pass -in $pull){
    & $smSDKPath $smParam | %{$pull = $_}
    
    $pull = $pull.Split(",")
    if((compare-object $initial $pull) -ne $null){

        $data = $data += @{Time=(get-date -Format "HH:mm:ss");Username=$pull[0];Address=$pull[1];Safe=$pull[2];PasswordChangeInProcess=$pull[3];StartChangeNotBefore=ConvertFrom-UnixTime($pull[4]);UserEmail=$pull[5];Password=$pull[6]}
        
        $save = $save + $pull[4]
        
        $initial = $pull
    
        $data | %{[PSCustomObject]$_} | Format-Table -AutoSize -Property Time,Password,Username,Address,Safe,UserEmail,PasswordChangeInProcess,StartChangeNotBefore
        }
    start-sleep -seconds 1
}

start-sleep -Seconds 11
& $smSDKPath $smParam | %{$newpull = $_}
$newpull = $newpull.Split(",")
$data = $data += @{Time=(get-date -Format "HH:mm:ss");Username=$newpull[0];Address=$newpull[1];Safe=$newpull[2];PasswordChangeInProcess=$newpull[3];StartChangeNotBefore=ConvertFrom-UnixTime($newpull[4]);UserEmail=$newpull[5];Password=$newpull[6]}
$data | %{[PSCustomObject]$_} | Format-Table -AutoSize -Property Time,Password,Username,Address,Safe,UserEmail,PasswordChangeInProcess,StartChangeNotBefore
