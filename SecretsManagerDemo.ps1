#This script will only work against a Credential Provider (CP) agent installed with the windows CLIPasswordSDK.exe

#region Verify and update these values
#SDK Path
$smPath = 'C:\Program Files (x86)\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe'

#Provider query variables
$AppID = 'TestApp1' #Enter the Application ID as listed in the Application page in the PVWA or via Users & Groups in the PrivateArk Client
$SafeName = 'P_HT_AAM_Safe' #Enter the safe name the target credential is stored in.  Ensure the provider user and application user ID have "List" and "Retrieve" access on the safe
$Address = 'ht.mtb' #Enter the address associated with the target credential
$UserName = 'SVC_AAMDemo' #Enter the username for the target credential

#endregion

#Modifying the output argument will break the table printing capability, please ensure to comment the line and create a new line rather than modifying the original
$OutputArg = 'PassProps.Username,PassProps.Address,PassProps.PolicyID,PasswordChangeInProcess,PassProps.StartChangeNotBefore,PassProps.OwnerEmail,Password'

#Do not modify the variables below
$data = @()
$time = 
$PassChangeInProcess = @()
$StartChangeNotBefore = @()

$smParam = 'getpassword', '/p',"AppDescs.AppID=$AppID", "/p","Query=Safe=$SafeName;Address=$Address;UserName=$UserName", '/p','FailRequestOnPasswordChange=False','/o',"$OutputArg"


# @FUNCTION@ ======================================================================================================================
# Name...........: ConvertFrom-UnixTime
# Description....: Convert from UnixTime
# Parameters.....: Unix Epoch Timestamp
# Return Values..: Human readable datetime
# =================================================================================================================================
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


#Initial retrieval of data

& $smPath $smParam | %{$initial = $_}

$initial = $initial.split(",")
$pull = $initial
$pass = $initial[6]

$data = $data += @{Time=(get-date -Format "HH:mm:ss");Username=$pull[0];Address=$pull[1];Safe=$pull[2];PasswordChangeInProcess=$pull[3];StartChangeNotBefore=ConvertFrom-UnixTime($pull[4]);UserEmail=$pull[5];Password=$pull[6]}
$data | %{[PSCustomObject]$_} | Format-Table -AutoSize -Property Time,Password,Username,Address,Safe,UserEmail,PasswordChangeInProcess,StartChangeNotBefore


$save = @()

while ($pass -in $pull){
    & $smPath $smParam | %{$pull = $_}
    
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
& $smPath $smParam | %{$newpull = $_}
$newpull = $newpull.Split(",")
$data = $data += @{Time=(get-date -Format "HH:mm:ss");Username=$newpull[0];Address=$newpull[1];Safe=$newpull[2];PasswordChangeInProcess=$newpull[3];StartChangeNotBefore=ConvertFrom-UnixTime($newpull[4]);UserEmail=$newpull[5];Password=$newpull[6]}
$data | %{[PSCustomObject]$_} | Format-Table -AutoSize -Property Time,Password,Username,Address,Safe,UserEmail,PasswordChangeInProcess,StartChangeNotBefore
