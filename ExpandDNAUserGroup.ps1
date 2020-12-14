#region Variables

$filePath = "C:\Users\brendan\Desktop\DNA Group Expansion\ServersDNAExport.Small.csv"
$outfile = "C:\Users\brendan\Desktop\DNA Group Expansion\ServersDNAExport.ExpandedGroups.csv"
$newfile = @()
<#$line = @{
    MachineName = ''
    Machine = ''
    Type = ''
    AccountName = ''
    AccountDisplayName = ''
    AccountType = ''
    AccountCategory = ''
    AccountGroup = ''
    PrivilegedDomainGroup = ''
    ServiceAccountType = ''
    ServiceAccountDescription = ''
    AccountState = ''
    OSVersion = ''
    Details = ''
}#>


#endregion



#region Functions
<#Function Append-CSV{

    #likely to be unused, is very slow
    
    param (
        [Parameter(Mandatory = $true)]
        [String[]]
        $output
    )

    process{
        Try{  $output | ConvertTo-CSV | Out-File -Append -FilePath $outfile  }
        catch{  write-host $_  }
    }
}#>

Function Calculate-UniqueGroups{

    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $fullLine
    )

    Begin{
        
        $GroupNames = @()    
    }

    Process{
    
        $GroupNames = $fullLine.PrivilegedDomainGroup.split(';')
    
        foreach(  $group in $groupnames  ){
            
            If(  $group -eq ''  ){
                $group = "NoGroup"
            }

            $updatedline = [PSCustomObject][Ordered]@{
                MachineName = $fullLine.MachineName
                MachineType = $fullLine.MachineType
                AccountName = $fullLine.AccountName
                AccountDisplayName = $fullLine.AccountDisplayName
                AccountType = $fullLine.AccountType
                AccountCategory = $fullLine.AccountCategory
                AccountGroup = $fullLine.AccountGroup
                PrivilegedDomainGroup = $group
                ServiceAccountType = $fullLine.ServiceAccountType
                ServiceAccountDescription = $fullLine.ServiceAccountDescription
                AccountState = $fullLine.AccountState
                OSVersion = $fullLine.OSVersion
                Details = $fullLine.Details
            }
            
            try{ $newfile += $updatedline }
            catch { $_
                write-host 'function' }
            Out-Null
        }


    }
}


#endregion


#Import CSV to pipeline
Import-CSV -Path $filePath | %{
    
    $this = $_
    #$this = @($_)
    if(  $this.PrivilegedDomainGroup -match '((.*);(.*))+'  ){  Calculate-UniqueGroups $this  }
    Else{  $newfile += $this  }
    Out-Null
}
#Read group name
