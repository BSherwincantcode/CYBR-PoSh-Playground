#region Variables

$filePath = "C:\Users\brendan\Desktop\DNA Group Expansion\ServersDNAExport.csv"
$outfile = "C:\Users\brendan\Desktop\DNA Group Expansion\ServersDNAExport.full.ExpandedGroups.csv"
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
    
        $GroupNames = $fullLine.'Privileged Domain Group'.split(';')
    
        foreach(  $group in $groupnames  ){
            
            If(  $group -eq ''  ){
                $group = "NoGroup"
            }

            $updatedline = [PSCustomObject][Ordered]@{
                'Machine Name' = $fullLine.'Machine Name'
                'Machine Type' = $fullLine.'Machine Type'
                'Account Name' = $fullLine.'Account Name'
                'Account Display Name' = $fullLine.'Account Display Name'
                'Account Type' = $fullLine.'Account Type'
                'Account Category' = $fullLine.'Account Category'
                'Account Group' = $fullLine.'Account Group'
                'Privileged Domain Group' = $group
                'Service Account Type' = $fullLine.'Service Account Type'
                'Service Account Description' = $fullLine.'Service Account Description'
                'Account State' = $fullLine.'Account State'
                'OS Version' = $fullLine.'OS Version'
                Details = $fullLine.Details
            }
            try{ $script:newfile += $updatedline } 
            catch { $_  }
        }


    }
}


#endregion


#Import CSV to pipeline
Import-CSV -Path $filePath | %{
    
    $this = $_
    if(  $this.'Privileged Domain Group' -match '((.*);(.*))+'  ){  Calculate-UniqueGroups $this  }
    Else{  $newfile += $this  }
}

$newfile | Export-Csv -Path $outfile -NoTypeInformation
#Read group name
