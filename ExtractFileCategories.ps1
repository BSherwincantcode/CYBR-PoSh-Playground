$xmlpath = "C:\Users\Administrator\Downloads\HealthCheck_0825\HealthCheck_0825\Policies.xml"
[xml]$policies = Get-Content $xmlpath
$xpath = 'PasswordVaultPolicies/Devices/Device/Policies/Policy'
$propsTable = @{}
$allprops = @()
$ExportDIR = "C:\Users\Administrator\Documents\"
$ExportFile = $ExportDIR + "PoliciesXML_PropsAnalaysis_" + (Get-Date -Format "MM-dd HHMM") + ".csv"


foreach($Policy in $policies.PasswordVaultPolicies.Devices.Device.Policies.Policy){ 

    [array]$props = ( $Policy.Properties.Required.Property | Select-Object -ExpandProperty Name )
    $props += ( $Policy.Properties.Optional.Property | Select-Object -ExpandProperty Name )
    $propstable.add($policy.ID,$props)
   
}

Add-Content -Path $ExportFile -Value "PolicyID,Property"
ForEach($ID in $propsTable.Keys){
    Foreach($prop in $propsTable.$ID){
        Add-Content -Path $ExportFile -Value ( $ID + "," + $prop )
    }
}
