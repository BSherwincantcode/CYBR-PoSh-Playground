
#region Initialize variables

$AccountsCSVPath = "C:\Users\Administrator\Documents\Accounts.csv"
$ExportDIR = "C:\Users\Administrator\Documents\"
$ExportFile = $ExportDIR + "Create-AllowedSafes_Output_" + (Get-Date -Format "MM-dd HHMM") + ".csv"
$PlatformSafe = @{}
$PlatformRegex = @{}
$header = "SafeName","PolicyID"

#endregion


#region Functions

Function Build-AllowedSafesStr{
    param (
        [Parameter(Mandatory = $true)]
        [String[]]
        $safeNames
    )

    # Defining the initial 
    Begin{
        $regexInit = "^("
        $regexTerm = ")$"
    }

    Process{
        [String]$allowedSafes = $regexInit
        ForEach($Safe in $safeNames){
            $allowedSafes = ($allowedSafes += ($Safe + "|"))
        }

        # removing trailing pipe and finalizing RegEx for return
        $allowedSafes = $allowedSafes.Substring(0,$allowedSafes.Length-1) + $regexTerm

        $allowedSafes
    }  
}

#endregion


# Build hashtable of Platforms and all associated safes
Import-CSV -Path $AccountsCSVPath | %{
    $obj = $_
    $i += 1
    #if($i -gt 5000){break}
    if($PlatformSafe.ContainsKey($obj.PolicyID)){
        If($PlatformSafe[$Obj.PolicyID] -Contains($obj.SafeName) -eq $false){
            $PlatformSafe.($obj.PolicyID) += $obj.SafeName
        }
    }
    Else{
        $PlatformSafe.Add($Obj.PolicyID,[System.Array]$obj.SafeName)
    }
}

# Feed hashtable to function to build and format the precise "AllowedSafes" parameter
$PlatformSafe.Keys | %{ 
    Try{
        $PlatformRegex.Add($_,(Build-AllowedSafesStr $PlatformSafe.$_)) 
    }
    Catch{ 
        write-host ("error with RegexArrayAdd`n" + $_) 
    } 
}


# Export results to CSV File
Try{$PlatformRegex.GetEnumerator() | select name,value | ConvertTo-Csv | Out-File -FilePath $ExportFile }
catch{ write-host $_ }
