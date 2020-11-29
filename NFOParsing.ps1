$system1
[xml]$nfodata = get-content -path "C:\Users\brendan\Desktop\Cust\server.nfo"

#region Variables and PSCustomObject
$srvinfo = @{
    ComputerName = ''
    OS = ''
    NumCPUs = 0
    RAM = ''
    CYBRRole = ''
}
$diskhash=@{}


$system1 = New-Object -TypeName PSObject -Property $srvinfo

$system1.ComputerName = ($nfodata.MsInfo.Category.Data | Where-Object {$_.ChildNodes.'#cdata-section' -eq 'System Name'}).Value.'#cdata-section'
$system1.OS = ($nfodata.MsInfo.Category.Data | Where-Object {$_.ChildNodes.'#cdata-section' -eq 'OS Name'}).Value.'#cdata-section'
$system1.RAM = ($nfodata.MsInfo.Category.Data | Where-Object {$_.ChildNodes.'#cdata-section' -eq 'Installed Physical Memory (RAM)'}).Value.'#cdata-section'
$system1.NumCPUs = ($nfodata.MsInfo.Category.Data | Where-Object {$_.ChildNodes.'#cdata-section' -eq 'Processor'}).Value.'#cdata-section' | Select-String -Pattern "(\d+) Core\(s\)" | ForEach-Object {$_.Matches.Groups[1].value} | Measure-Object -sum | Select-Object -ExpandProperty Sum
<#$disks = #>($xml.MsInfo.Category.Category.Category.Category | Where-Object {$_.Name -eq "Drives"}).Data.Value.'#cdata-section' | %{
    switch -regex ($_) { 
        
        '\w:' {
            if($diskHash.Count -eq 5)
            {
                #$driveletter = $diskHash.letter
                If([float]$diskhash.longval1 -gt [float]$diskhash.longval2){
                    $system1 | Add-Member -NotePropertyName ($diskhash.letter+'_Total_Stor') -NotePropertyValue $diskhash.shortval1 -Force
                    $system1 | Add-Member -NotePropertyName ($diskhash.letter+'_Avail_Stor') -NotePropertyValue $diskhash.shortval2 -force
                }
                Else{
                    $system1 | Add-Member -NotePropertyName ($diskhash.letter+'_Total_Stor') -NotePropertyValue $diskhash.shortval2 -Force
                    $system1 | Add-Member -NotePropertyName ($diskhash.letter+'_Avail_Stor') -NotePropertyValue $diskhash.shortval1 -Force
                }
                Remove-Variable diskhash
                $diskhash = @{}
                $diskhash["letter"]=$matches[0].Substring(0,1)
            }
            else
            {
                Remove-Variable diskhash
                $diskhash = @{}
                $diskhash["letter"]=$matches[0].Substring(0,1)
            }
        }
        '(\d+.\d+ \wB) \(((\d{1,3},?)+) bytes\)'{
            
            
            if($diskHash.Count -eq 1){
                $diskHash["shortval1"] = $matches[1]
                $diskhash["longval1"] = $matches[2] -replace ',',''
            }
            elseif($diskHash.Count -eq 3){
                $diskhash["shortval2"] = $matches[1]
                $diskhash["longval2"] = $matches[2] -replace ',',''
            }
            else{
                Write-Host "Error with disk analysis"
            }
                
        }
    }
}
# = ($nfodata.MsInfo.Category.Data | Where-Object {$_.ChildNodes.'#cdata-section' -eq 'Display_Name'}).Value.'#cdata-section'
