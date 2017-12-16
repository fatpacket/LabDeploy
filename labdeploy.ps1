param(
	[Parameter(Mandatory=$true)] [String]$configFile,
	[switch]$deployESXi,
	[switch]$deployVCSA,
	[switch]$configureVCSA,
	[switch]$licenseVCSA,
	[switch]$configureHosts,
	[switch]$configureVDSwitch,
	[switch]$configureVSAN,
	[switch]$deployNSXManager,
	[switch]$configureNSX,
	[switch]$deployvRAAppliance,
	[switch]$patchESXi
)

if($psboundparameters.count -eq 1) {
	# Only the configFile is passed, set all steps accordingly
	$deployESXi = $true
	$deployVCSA = $true
	$configureVCSA = $true
	$licenseVCSA = $true
	$configureHosts = $true
	$configureVDSwitch = $true
	$configureVSAN = $true
	$DeployNSXManager = $true
	$configureNSX = $true
	$deployvRAAppliance =$false
	$patchESXi = $false
}

# Hat tips and thanks go to...
# Sam McGeown http://www.definit.co.uk && https://github.com/sammcgeown/Pod-Deploy 
# 
# Sam has done some great work over at his blog and these scripts in original form have been a great inspiration for me to work
# with and tweak. The snippets code in these scripts has also been inspired by the following
#
# William Lam http://www.virtuallyghetto.com/2016/11/vghetto-automated-vsphere-lab-deployment-for-vsphere-6-0u2-vsphere-6-5.html
# Rawlinson Riviera http://www.punchingclouds.com/2016/03/24/vmware-virtual-san-automated-deployments-powercli/
# Brian Graf http://www.vtagion.com/automatically-deploy-nsx-connect-vcenter/
# Anthony Burke https://networkinferno.net/license-nsx-via-automation-with-powercli
#
# Thank you for all the great works and supporting the community the way each of you does
# 
# Brant Scalan - http://www.fatpacket.net/blog  && https://github.com/N3tb0ss
#

# Import the JSON Config File
$podConfig = (get-content $($configFile) -Raw) | ConvertFrom-Json

$VCSAInstaller  = "$($podConfig.sources.VCSAInstaller)"
$ESXiAppliance  = "$($podConfig.sources.ESXiAppliance)"
$NSXAppliance   = "$($podConfig.sources.NSXAppliance)"
#$vRAAppliance   = "$($podConfig.sources.vRAAppliance)"
#$ESXi65aBundle	= "$($podConfig.sources.ESXiPatch)"

# Log File
$verboseLogFile = $podConfig.general.log

$StartTime = Get-Date


Function Set-VSANSilentHealthChecks {
	<#
    .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  VMware
        Blog:          www.virtuallyghetto.com
        Twitter:       @lamw
        ===========================================================================
    .DESCRIPTION
        This function retreives the vSAN software version for both VC/ESXi
    .PARAMETER Cluster
        The name of a vSAN Cluster
    .PARAMETER Test
        The list of vSAN Health CHeck IDs to silence or re-enable
    .EXAMPLE
        Set-VSANSilentHealthChecks -Cluster VSAN-Cluster -Test controlleronhcl -Disable
    .EXAMPLE
        Set-VSANSilentHealthChecks -Cluster VSAN-Cluster -Test controlleronhcl,controllerfirmware -Disable
    .EXAMPLE
        Set-VSANSilentHealthChecks -Cluster VSAN-Cluster -Test controlleronhcl -Enable
    .EXAMPLE
        Set-VSANSilentHealthChecks -Cluster VSAN-Cluster -Test controlleronhcl,controllerfirmware -Enable
	#>
	param(
        [Parameter(Mandatory=$true)][String]$Cluster,
        [Parameter(Mandatory=$true)][String[]]$Test,
        [Switch]$Enabled,
        [Switch]$Disabled
    )
    $vchs = Get-VSANView -Id "VsanVcClusterHealthSystem-vsan-cluster-health-system"
    $cluster_view = (Get-Cluster -Name $Cluster).ExtensionData.MoRef

    if($Enabled) {
        $vchs.VsanHealthSetVsanClusterSilentChecks($cluster_view,$null,$Test)
    } else {
        $vchs.VsanHealthSetVsanClusterSilentChecks($cluster_view,$Test,$null)
    }
}
Function Write-Log {
	param(
		[Parameter(Mandatory=$true)]
		[String]$Message,
		[switch]$Warning,
		[switch]$Info
	)
	$timeStamp = Get-Date -Format "dd-MM-yyyy hh:mm:ss"
	Write-Host -NoNewline -ForegroundColor White "[$timestamp]"
	if($Warning){
		Write-Host -ForegroundColor Yellow " WARNING: $message"
	} elseif($Info) {
		Write-Host -ForegroundColor White " $message"
	}else {
		Write-Host -ForegroundColor Green " $message"
	}
	$logMessage = "[$timeStamp] $message" | Out-File -Append -LiteralPath $verboseLogFile
}

function Get-VCSAConnection {
	param(
		[string]$vcsaName,
		[string]$vcsaUser,
		[string]$vcsaPassword
	)
	Write-Log "Getting connection for $($vcsaName)"
	$existingConnection =  $global:DefaultVIServers | where-object -Property Name -eq -Value $vcsaName
	if($existingConnection -ne $null) {
		return $existingConnection;
	} else {
        $connection = Connect-VIServer -Server $vcsaName -User $vcsaUser -Password $vcsaPassword -WarningAction SilentlyContinue;
		return $connection;
	}
}

function Close-VCSAConnection {
	param(
		[string]$vcsaName
	)
	if($vcsaName.Length -le 0) {
		if($Global:DefaultVIServers -le 0) {
	        Write-Log -Message "Disconnecting from all vCenter Servers"
			Disconnect-VIServer -Server $Global:DefaultVIServers -Confirm:$false
		}
	} else {
		$existingConnection =  $global:DefaultVIServers | where-object -Property Name -eq -Value $vcsaName
        if($existingConnection -ne $null) {
            Write-Log -Message "Disconnecting from $($vcsaName)"
			Disconnect-VIServer -Server $existingConnection -Confirm:$false;
        } else {
            Write-Log -Message "Could not find an existing connection named $($vcsaName)" -Warning
        }
	}
}
function Get-PodFolder {
	param(
		$vcsaConnection,
		[string]$folderPath
	)
	$folderArray = $folderPath.split("/")
	$parentFolder = Get-Folder -Server $vcsaConnection -Name vm
	foreach($folder in $folderArray) {
		$folderExists = Get-Folder -Server $vcsaConnection | Where-Object -Property Name -eq -Value $folder
		if($folderExists -ne $null) {
			$parentFolder = $folderExists
		} else {
			$parentFolder = New-Folder -Name $folder -Location $parentFolder
		}
	}
	return $parentFolder
}

# Header
Write-Host -ForegroundColor Magenta "`nFatPacket Labs - Where Rebuilds Happen`n"

if($deployESXi) {
	Write-Log "#### Deploying Nested ESXi VMs ####"
	$pVCSA = Get-VCSAConnection -vcsaName $podConfig.target.server -vcsaUser $podConfig.target.user -vcsaPassword $podConfig.target.password
	$pCluster = Get-Cluster -Name $podConfig.target.cluster -Server $pVCSA
	$pDatastore = Get-Datastore -Name $podConfig.target.datastore -Server $pVCSA
	$pPortGroup = Get-VDPortgroup -Name $podConfig.target.portgroup -Server $pVCSA
	$pFolder = Get-PodFolder -vcsaConnection $pVCSA -folderPath $podConfig.target.folder

	if ($pDatastore.Type -eq "vsan") {
		Write-Log "VSAN Datastore detected, checking Fake SCSI Reservations"
		$pHosts = Get-VMHost -Location $pCluster
		foreach($pHost in $pHosts) {
			$Setting = Get-AdvancedSetting -Entity $pHost -Name "VSAN.FakeSCSIReservations"
			if($Setting.Value -ne 1) {
				Write-Log "Setting FakeSCSIReservations on $($pHost)"
				Get-AdvancedSetting -Entity $pHost -Name "VSAN.FakeSCSIReservations" | Set-AdvancedSetting -Value 1 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
			}
		}
	}

	$deployTasks = @()

	$podConfig.esxi.hosts | ForEach-Object {
		Write-Log "Selecting a host from $($podConfig.target.cluster)"
		$pESXi = $pCluster | Get-VMHost -Server $pVCSA | where { $_.ConnectionState -eq "Connected" } | Get-Random
		Write-Log "$($pESXi) selected."

		$nestedESXiName = $_.name
		$nestedESXiIPAddress = $_.ip

		if((Get-VM | Where-Object -Property Name -eq -Value $nestedESXiName) -eq $null) {
			$ovfConfig = Get-ovfConfiguration -Ovf $ESXiAppliance
			$ovfConfig.Common.guestinfo.hostname.Value = $nestedESXiName
			$ovfConfig.Common.guestinfo.ipaddress.Value = $nestedESXiIPAddress
			$ovfConfig.Common.guestinfo.netmask.Value = $podConfig.target.network.netmask
			$ovfConfig.Common.guestinfo.gateway.Value = $podConfig.target.network.gateway
			$ovfConfig.Common.guestinfo.dns.Value = $podConfig.target.network.dns
			$ovfConfig.Common.guestinfo.domain.Value = $podConfig.target.network.domain
			$ovfConfig.Common.guestinfo.ntp.Value = $podConfig.target.network.ntp
			$ovfConfig.Common.guestinfo.syslog.Value = $podConfig.general.syslog
			$ovfConfig.Common.guestinfo.password.Value = $podConfig.general.password
			$ovfConfig.Common.guestinfo.ssh.Value = $podConfig.general.ssh
			$ovfConfig.Common.guestinfo.createvmfs.Value = $podConfig.esxi.createVMFS
			$ovfConfig.NetworkMapping.VM_Network.Value = $pPortGroup

			Write-Log "Deploying Nested ESXi VM $($nestedESXiName)"
			#$deployTasks[(Import-VApp -Server $pVCSA -VMHost $pESXi -Source $ESXiAppliance -ovfConfiguration $ovfConfig -Name $nestedESXiName -Location $pCluster -Datastore $pDatastore -DiskStorageFormat thin -RunAsync -ErrorAction SilentlyContinue).Id] = $nestedESXiName
			$task = Import-VApp -Server $pVCSA -VMHost $pESXi -Source $ESXiAppliance -ovfConfiguration $ovfConfig -Name $nestedESXiName -Location $pCluster -Datastore $pDatastore -InventoryLocation $pFolder -DiskStorageFormat thin -RunAsync -ErrorAction SilentlyContinue
			$deployTasks += $task
		} else {
			Write-Log "Nested ESXi host $($nestedESXiName) exists, skipping" -Warning
		}
	}

	$taskCount = $deployTasks.Count
	while($taskCount -gt 0) {
		Write-Log "Task count $($taskCount)"
		$deployTasks | ForEach-Object {
			Write-Log -Message "`t- Task $($_.Id) - $($_.State) - $($_.PercentComplete)%"
			if($_.State -eq "Success") {
				# Deployment Completed
				Write-Log "Deployment task $($_.Id) ($($_.Result)) succeeded, configuring"

				$nestedESXiVM = Get-VM -Name $_.Result -Server $pVCSA

				Write-Log "Updating vCPU Count to $($podConfig.esxi.cpu) & vMEM to $($podConfig.esxi.ram) GB"
				$nestedESXiVM | Set-VM -NumCpu $podConfig.esxi.cpu -MemoryGB $podConfig.esxi.ram -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

				Write-Log "Updating vSAN Caching VMDK size to $($podConfig.esxi.cacheDisk) GB"
				# Work around for VSAN issue with not enough disk space - delete and add new disk
				Get-HardDisk -VM $nestedESXiVM | where-object -Property "CapacityGB" -eq -Value 4 | Remove-HardDisk -DeletePermanently -Confirm:$false
				New-HardDisk -VM $nestedESXiVM -Persistence persistent -SizeGB $podConfig.esxi.cacheDisk -StorageFormat Thin | Out-File -Append -LiteralPath $verboseLogFile

				Write-Log "Updating vSAN Capacity VMDK size to $($podConfig.esxi.capacityDisk) GB"
				# Work around for VSAN issue with not enough disk space - delete and add new disk
				Get-HardDisk -VM $nestedESXiVM | where-object -Property "CapacityGB" -eq -Value 8 | Remove-HardDisk -DeletePermanently -Confirm:$false
				New-HardDisk -VM $nestedESXiVM -Persistence persistent -SizeGB $podConfig.esxi.capacityDisk -StorageFormat Thin | Out-File -Append -LiteralPath $verboseLogFile

				# Ensure the disks are marked as SSD
				New-AdvancedSetting -Entity $nestedESXiVM -Name 'scsi0:0.virtualSSD' -Value $true -Confirm:$false -Force | Out-File -Append -LiteralPath $verboseLogFile
				New-AdvancedSetting -Entity $nestedESXiVM -Name 'scsi0:1.virtualSSD' -Value $true -Confirm:$false -Force | Out-File -Append -LiteralPath $verboseLogFile
				New-AdvancedSetting -Entity $nestedESXiVM -Name 'scsi0:2.virtualSSD' -Value $true -Confirm:$false -Force | Out-File -Append -LiteralPath $verboseLogFile
				
				# Import-vApp now includes -InventoryLocation
				# Write-Log "Moving $nestedESXiName to $($pFolder.Name) folder"
				# Move-VM -VM $nestedESXiVM -Destination $pFolder | Out-File -Append -LiteralPath $verboseLogFile

				Write-Log "Powering On $nestedESXiName"
				Start-VM -VM $nestedESXiVM -Confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile

				$successTask = $_
				$deployTasks = $deployTasks | Where-Object $_.Id -ne ($successTask.Id)
				$taskCount--

			} elseif($_.State -eq "Error") {
				Write-Log -Message " failed to deploy" -Warning
				$failedTask = $_
				$deployTasks = $deployTasks | Where-Object $_.Id -ne ($failedTask.Id)
				$taskCount--
			}
		}
		Start-Sleep 30
	}
	Close-VCSAConnection -vcsaName $podConfig.target.server
	# Write-Log "#### Nested ESXi VMs Deployed ####"
}

if($deployVCSA) {
	Write-Log "#### Deploying VCSA ####"
	$pVCSA = Get-VCSAConnection -vcsaName $podConfig.target.server -vcsaUser $podConfig.target.user -vcsaPassword $podConfig.target.password
	$pCluster = Get-Cluster -Name $podConfig.target.cluster -Server $pVCSA
	$pDatastore = Get-Datastore -Name $podConfig.target.datastore -Server $pVCSA
	$pPortGroup = Get-VDPortgroup -Name $podConfig.target.portgroup -Server $pVCSA
	$pFolder = Get-PodFolder -vcsaConnection $pVCSA -folderPath $podConfig.target.folder

	# My Environment has vApp's unable to disable DRS
	#Write-Log "Disabling DRS on $($podConfig.target.cluster)"
	# $pCluster | Set-Cluster -DrsEnabled:$false -Confirm:$false |  Out-File -Append -LiteralPath $verboseLogFile

	if($podConfig.psc -ne $null) {
		Write-Log "#### Deploying external PSC ####"
		$config = (Get-Content -Raw "$($VCSAInstaller)\vcsa-cli-installer\templates\install\PSC_first_instance_on_VC.json") | convertfrom-json
		$config.'new.vcsa'.vc.hostname = $podConfig.target.server
		$config.'new.vcsa'.vc.username = $podConfig.target.user
		$config.'new.vcsa'.vc.password = $podConfig.target.password
		$config.'new.vcsa'.vc.datacenter = @($podConfig.target.datacenter)
		$config.'new.vcsa'.vc.datastore = $podConfig.target.datastore
		$config.'new.vcsa'.vc.target = @($podConfig.target.cluster)
		$config.'new.vcsa'.vc.'deployment.network' = $podConfig.target.portgroup
		$config.'new.vcsa'.appliance.'thin.disk.mode' = $true
		$config.'new.vcsa'.appliance.'deployment.option' = $podConfig.psc.deploymentSize
		$config.'new.vcsa'.appliance.name = $podConfig.psc.name
		$config.'new.vcsa'.network.'system.name' = $podConfig.psc.hostname
		$config.'new.vcsa'.network.'ip.family' = "ipv4"
		$config.'new.vcsa'.network.mode = "static"
		$config.'new.vcsa'.network.ip = $podConfig.psc.ip
		$config.'new.vcsa'.network.'dns.servers'[0] = $podConfig.target.network.dns
		$config.'new.vcsa'.network.prefix = $podConfig.target.network.prefix
		$config.'new.vcsa'.network.gateway = $podConfig.target.network.gateway
		$config.'new.vcsa'.os.'ssh.enable' = $podConfig.general.ssh
		$config.'new.vcsa'.os.password = $podConfig.psc.rootPassword
		$config.'new.vcsa'.sso.password = $podConfig.psc.sso.password
		$config.'new.vcsa'.sso.'domain-name' = $podConfig.psc.sso.domain
		$config.'new.vcsa'.sso.'site-name' = $podConfig.psc.sso.site
		if($podConfig.psc.sso.replicationPartner.length -gt 0) {
			# Join existing domain
			Write-Log "PSC will join replicate to $($podConfig.psc.sso.replicationPartner) "
			$config.'new.vcsa'.sso | Add-Member -Name "first-instance" -Value $false -MemberType NoteProperty
			$config.'new.vcsa'.sso | Add-Member -Name "sso.port" -Value "443" -MemberType NoteProperty
			$config.'new.vcsa'.sso | Add-Member -Name "replication-partner-hostname" -Value $podConfig.psc.sso.replicationPartner -MemberType NoteProperty
		}
		Write-Log "Creating PSC JSON Configuration file for deployment"
		$config | ConvertTo-Json | Set-Content -Path "$($ENV:Temp)\psctemplate.json"

		if((Get-VM | Where-Object -Property Name -eq -Value $podConfig.psc.name) -eq $null) {
			Write-Log "Deploying OVF, this may take a while..."
			Invoke-Expression "$($VCSAInstaller)\vcsa-cli-installer\win32\vcsa-deploy.exe install --no-esx-ssl-verify --accept-eula --acknowledge-ceip $($ENV:Temp)\psctemplate.json" | Out-File -Append -LiteralPath $verboseLogFile
			$vcsaDeployOutput | Out-File -Append -LiteralPath $verboseLogFile
			Write-Log "Moving $($podConfig.psc.name) to $($podConfig.target.folder)"
			if((Get-VM | where {$_.name -eq $podConfig.psc.name}) -eq $null) {
				throw "Could not find VCSA VM. The script was unable to find the deployed VCSA"
			}
			Get-VM -Name $podConfig.psc.name | Move-VM -InventoryLocation $pFolder |  Out-File -Append -LiteralPath $verboseLogFile
		} else {
			Write-Log "PSC exists, skipping" -Warning
		}

	}
	if($podConfig.vcsa -ne $null) {
		if($podConfig.psc -ne $null) {
			Write-Log "VCSA with external PSC"
			$config = (Get-Content -Raw "$($VCSAInstaller)\vcsa-cli-installer\templates\install\vCSA_on_VC.json") | convertfrom-json
			# External PSC Specific config
			$config.'new.vcsa'.sso.'sso.port' = "443"
			$config.'new.vcsa'.sso.'platform.services.controller' = $podConfig.psc.ip
		} else {
			Write-Log "VCSA with embedded PSC"
			$config = (Get-Content -Raw "$($VCSAInstaller)\vcsa-cli-installer\templates\install\embedded_vCSA_on_VC.json") | convertfrom-json
			# Embedded PSC Specific config
			$config.'new.vcsa'.sso.'site-name' = $podConfig.vcsa.sso.site
		}
		$config.'new.vcsa'.vc.hostname = $podConfig.target.server
		$config.'new.vcsa'.vc.username = $podConfig.target.user
		$config.'new.vcsa'.vc.password = $podConfig.target.password
		$config.'new.vcsa'.vc.datacenter = @($podConfig.target.datacenter)
		$config.'new.vcsa'.vc.datastore = $podConfig.target.datastore
		$config.'new.vcsa'.vc.target = @($podConfig.target.cluster)
		$config.'new.vcsa'.vc.'deployment.network' = $podConfig.target.portgroup
		$config.'new.vcsa'.os.'ssh.enable' = $podConfig.general.ssh
		$config.'new.vcsa'.os.password = $podConfig.vcsa.rootPassword
		$config.'new.vcsa'.appliance.'thin.disk.mode' = $true
		$config.'new.vcsa'.appliance.'deployment.option' = $podConfig.vcsa.deploymentSize
		$config.'new.vcsa'.appliance.name = $podConfig.vcsa.name
		$config.'new.vcsa'.network.'system.name' = $podConfig.vcsa.hostname
		$config.'new.vcsa'.network.'ip.family' = "ipv4"
		$config.'new.vcsa'.network.mode = "static"
		$config.'new.vcsa'.network.ip = $podConfig.vcsa.ip
		$config.'new.vcsa'.network.'dns.servers'[0] = $podConfig.target.network.dns
		$config.'new.vcsa'.network.prefix = $podConfig.target.network.prefix
		$config.'new.vcsa'.network.gateway = $podConfig.target.network.gateway
		$config.'new.vcsa'.sso.password = $podConfig.vcsa.sso.password
		$config.'new.vcsa'.sso.'domain-name' = $podConfig.vcsa.sso.domain
		Write-Log "Creating VCSA JSON Configuration file for deployment"
		$config | ConvertTo-Json | Set-Content -Path "$($ENV:Temp)\vctemplate.json"
		if((Get-VM | Where-Object -Property Name -eq -Value $podConfig.vcsa.name) -eq $null) {
			Write-Log "Deploying OVF, this may take a while..."
			Invoke-Expression "$($VCSAInstaller)\vcsa-cli-installer\win32\vcsa-deploy.exe install --no-esx-ssl-verify --accept-eula --acknowledge-ceip $($ENV:Temp)\vctemplate.json" | Out-File -Append -LiteralPath $verboseLogFile
			$vcsaDeployOutput | Out-File -Append -LiteralPath $verboseLogFile
			Write-Log "Moving $($podConfig.vcsa.name) to $($podConfig.target.folder)"
			if((Get-VM | where {$_.name -eq $podConfig.vcsa.name}) -eq $null) {
				throw "Could not find VCSA VM. The script was unable to find the deployed VCSA"
			}
			Get-VM -Name $podConfig.vcsa.name | Move-VM -InventoryLocation $pFolder |  Out-File -Append -LiteralPath $verboseLogFile
		} else {
			Write-Log "VCSA exists, skipping" -Warning
		}
		# My environment has vApps unable to disable DRS
		# Write-Log "Enabling DRS on $($podConfig.target.cluster)"
		# $pCluster | Set-Cluster -DrsEnabled:$true -Confirm:$false |  Out-File -Append -LiteralPath $verboseLogFile
	}
	Close-VCSAConnection -vcsaName $podConfig.target.server
}


if($configureVCSA) {
	Write-Log "#### Configuring VCSA ####"
	$nVCSA = Get-VCSAConnection -vcsaName $podConfig.vcsa.ip -vcsaUser "administrator@$($podConfig.vcsa.sso.domain)" -vcsaPassword $podConfig.vcsa.sso.password

	Write-Log "Configuring Datacenter and Cluster"
	Write-Log "Creating Datacenter $($podConfig.vcsa.datacenter)"
	$nDatacenter = (Get-Datacenter -Server $nVCSA | Where-Object -Property Name -eq -Value $podConfig.vcsa.datacenter)
	if($nDatacenter -eq $null) {
		$nDatacenter = New-Datacenter -Server $nVCSA -Name $podConfig.vcsa.datacenter -Location (Get-Folder -Type Datacenter -Server $nVCSA)
	} else {
		Write-Log "Datacenter exists, skipping" -Warning
	}
	Write-Log "Creating VSAN Cluster $($podConfig.vcsa.cluster)"
	$nCluster = Get-Cluster -Server $nVCSA | Where-object -Property Name -eq -Value $podConfig.vcsa.cluster
	if($nCluster -eq $null) {
		$nCluster = New-Cluster -Server $nVCSA -Name $podConfig.vcsa.cluster -Location $nDatacenter -DrsEnabled
	} else {
		Write-Log "Cluster exists, skipping" -Warning
	}

	if($licenseVCSA) {
		Write-Log "Licensing vSphere"
		$serviceInstance = Get-View ServiceInstance -Server $nVCSA
		$licenseManagerRef=$serviceInstance.Content.LicenseManager
		$licenseManager=Get-View $licenseManagerRef
		$licenseManager.AddLicense($podConfig.license.vcenter,$null) |  Out-File -Append -LiteralPath $verboseLogFile
		$licenseManager.AddLicense($podConfig.license.vsphere,$null) |  Out-File -Append -LiteralPath $verboseLogFile
		$licenseManager.AddLicense($podConfig.license.vsan,$null) |  Out-File -Append -LiteralPath $verboseLogFile
		# $licenseManager.AddLicense($podConfig.license.nsx,$null) |  Out-File -Append -LiteralPath $verboseLogFile
		$licenseAssignmentManager = Get-View $licenseManager.LicenseAssignmentManager
		Write-Log "Assigning vCenter Server License"
		try {
			$licenseAssignmentManager.UpdateAssignedLicense($nVCSA.InstanceUuid, $podConfig.license.vcenter, $null) | Out-File -Append -LiteralPath $verboseLogFile
		}
		catch {
			$ErrorMessage = $_.Exception.Message
			Write-Log $ErrorMessage -Warning
		}
	}

	if($configureHosts) {
		Write-Log "## Adding hosts to cluster ##"
		$nCluster = Get-Cluster -Name $podConfig.vcsa.cluster -Server $nVCSA
		$podConfig.esxi.hosts | ForEach-Object {
			$nestedESXiName = $_.name
			$nestedESXiIPAddress = $_.ip
			Write-Log "Adding ESXi host $nestedESXiIPAddress to Cluster"
			if((Get-VMHost -Server $nVCSA | Where-Object -Property Name -eq -Value $nestedESXiIPAddress) -eq $null) {
				Add-VMHost -Server $nVCSA -Location $nCluster -User "root" -Password $podConfig.general.password -Name $nestedESXiIPAddress -Force | Set-VMHost -LicenseKey $podConfig.license.vsphere -State "Maintenance" | Out-File -Append -LiteralPath $verboseLogFile
			} else {
				Write-Log "Host exists, skipping" -Warning
			}
		}
		Write-Log "Exiting host maintenance mode"
		Get-VMHost -Server $nVCSA | Set-VMHost -State Connected | Out-Null
	}

	if($configureVDSwitch) {
		Write-Log "## Configuring Distributed Switching ##"
		$nHosts = Get-VMHost -Location $podConfig.vcsa.cluster -Server $nVCSA
		$nDatacenter = Get-Datacenter -Name $podConfig.vcsa.datacenter -Server $nVCSA
		$distributedSwitch = Get-VDSwitch -Server $nVCSA | Where-Object -Property Name -eq -Value $podConfig.vcsa.distributedSwitch
		if($distributedSwitch -eq $null) {
			Write-Log "Creating distributed switch"
			$distributedSwitch = New-VDSwitch -Name $podConfig.vcsa.distributedSwitch -Location $nDatacenter -Server $nVCSA -NumUplinkPorts 2
			Start-Sleep -Seconds 20 # Pause reduces failures
		} else {
			Write-Log "Distributed switch exists, skipping" -Warning
		}

		Write-Log "Adding hosts to distributed switch"
		foreach ($nHost in $nHosts) {
			if(($distributedSwitch | Get-VMHost | where {$_.Name -eq $nHost.Name}) -eq $null) {
				Add-VDSwitchVMHost -VDSwitch $distributedSwitch -VMHost $nHost
				$pause = 20
			} else {
				Write-Log "$($nHost) is already added to VDS" -Warning
				$pause = 1
			}
		}
		Start-Sleep -Seconds $pause # Pause reduces failures

		$dvPortGroup = Get-VDPortgroup | Where-Object -Property Name -eq -Value $podConfig.vcsa.portgroup
		if($dvPortGroup -eq $null) {
			Write-Log "Creating distributed port group"
			$dvPortGroup = New-VDPortgroup -Name $podConfig.vcsa.portgroup -NumPorts 128 -VDSwitch $distributedSwitch
			$pause = 20
		} else {
			Write-Log "Distributed port group exists, skipping" -Warning
			$pause = 1
		}
		Start-Sleep -Seconds $pause # Pause reduces failures

		foreach($nHost in $nHosts) {
			if((Get-VMHostNetworkAdapter -DistributedSwitch (Get-VDSwitch -Name $podConfig.vcsa.distributedSwitch ) | where { $_.VMHost.Name -eq $nHost.Name -and $_.DeviceName -eq "vmnic1"}) -eq $NULL) {
				Write-Log "Adding $($nHost.Name) vmnic1 to distributed switch"
				Add-VDSwitchPhysicalNetworkAdapter -VMHostNetworkAdapter (Get-VMHostNetworkAdapter -Name "vmnic1" -VMHost $nHost) -DistributedSwitch $distributedSwitch -Confirm:$false
				$pause = 20
			} else {
				Write-Log "$($nHost.Name) vmnic1 is already assigned to $($podConfig.vcsa.distributedSwitch)" -Warning
				$pause = 1
			}
		}
		Start-Sleep -Seconds $pause # Pause reduces failures

		foreach($nHost in $nHosts) {			
			Write-Log "Migrating $($nHost.Name) VMKernel to distributed switch"
			$VMHNA = Get-VMHostNetworkAdapter -VMHost $nHost -Name vmk0
			if($VMHNA.PortGroupName -eq $podConfig.vcsa.portgroup) {
				Write-Log "vmk0 on $($nHost.Name) is already assigned to the port group $($dvPortGroup)" -Warning
				$pause = 1
			} else {
				Set-VMHostNetworkAdapter -PortGroup $dvPortGroup -VirtualNic (Get-VMHostNetworkAdapter  -Name vmk0 -VMHost $nHost) -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
				$pause = 20
			}
		}
		Start-Sleep -Seconds $pause # Pause reduces failures

		foreach($nHost in $nHosts) {
			if((Get-VMHostNetworkAdapter -DistributedSwitch (Get-VDSwitch -Name $podConfig.vcsa.distributedSwitch ) | where { $_.VMHost.Name -eq $nHost.Name -and $_.DeviceName -eq "vmnic0"}) -eq $NULL) {
				Write-Log "Moving $($nHost.Name) vmnic0 to distributed switch"
				Add-VDSwitchPhysicalNetworkAdapter -VMHostNetworkAdapter (Get-VMHostNetworkAdapter -Name "vmnic0" -VMHost $nHost) -DistributedSwitch $distributedSwitch -Confirm:$false
				$pause = 20
			} else {
				Write-Log "$($nHost.Name) vmnic0 is already assigned to $($podConfig.vcsa.distributedSwitch)" -Warning
				$pause = 1
			}
		}
		Start-Sleep -Seconds $pause # Pause reduces failures

		foreach($nHost in $nHosts) {
			if((Get-VMHost $nHost | Get-VMHostNetworkAdapter -VMKernel | Select vmotionenabled) -ne $false) {
				Write-Log "Enabling vMotion on $($nHost.Name) vmk0"
				Get-VMHost $nHost | Get-VMHostNetworkAdapter -VMkernel -Name "vmk0" | Set-VMHostNetworkAdapter -VmotionEnabled $true -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
				$pause = 20
			} else {
				Write-Log "vMotion already enabled on vmk0 for host $($nHost.Name)" -Warning
				$pause = 1
			}
		}
		Start-Sleep -Seconds $pause # Pause reduces failures

		Write-Log "Removing standard vSwitches"
		Get-VirtualSwitch -Server $nVCSA -Standard | Remove-VirtualSwitch -Confirm:$false
	}

	if($configureVSAN) {
		Write-Log "## Configuring VSAN ##"
		$VSANCluster = Get-Cluster -Name $podConfig.vcsa.cluster -Server $nVCSA | Out-File -Append -LiteralPath $verboseLogFile
		if($VSANCluster.VsanEnabled) {
			Write-Log "VSAN is enabled, skipping" -Warning
		} else {
			Set-Cluster -Cluster $podConfig.vcsa.cluster -VsanEnabled:$true -VsanDiskClaimMode Manual -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
			Write-Log "Assigning VSAN License"
			$serviceInstance = Get-View ServiceInstance -Server $nVCSA
			$licenseManagerRef=$serviceInstance.Content.LicenseManager
			$licenseManager=Get-View $licenseManagerRef
			$licenseAssignmentManager = Get-View $licenseManager.LicenseAssignmentManager
			$clusterRef = (Get-Cluster -Server $nVCSA -Name $podConfig.vcsa.cluster | get-view).MoRef
			try {
				$licenseAssignmentManager.UpdateAssignedLicense(($clusterRef.value), $podConfig.license.vsan, $null) | Out-File -Append -LiteralPath $verboseLogFile
			}
			catch {
				$ErrorMessage = $_.Exception.Message
				Write-Log $ErrorMessage -Warning
			}
		}
		
		$nHosts = Get-VMHost -Server $nVCSA -Location $podConfig.vcsa.cluster
		foreach ($nHost in $nHosts) {
		 	$luns = $nHost | Get-ScsiLun | Select-Object CanonicalName, CapacityGB
		 	if((Get-VsanDiskGroup -VMHost $nHost) -eq $null) {
		 		Write-Log "Querying ESXi host disks to create VSAN Diskgroups"
		 		foreach ($lun in $luns) {
		 			if(([int]($lun.CapacityGB)).toString() -eq "$($podConfig.esxi.cacheDisk)") {
		 				$vsanCacheDisk = $lun.CanonicalName
		 			}
		 			if(([int]($lun.CapacityGB)).toString() -eq "$($podConfig.esxi.capacityDisk)") {
		 				$vsanCapacityDisk = $lun.CanonicalName
		 			}
		 		}
		 		Write-Log "Creating VSAN DiskGroup for $nHost"
		 		New-VsanDiskGroup -Server $nVCSA -VMHost $nHost -SsdCanonicalName $vsanCacheDisk -DataDiskCanonicalName $vsanCapacityDisk | Out-File -Append -LiteralPath $verboseLogFile
			} else {
				Write-Log "VSAN Diskgroup already exists" -Warning
			}
		} 
		# Diabled VSAN checks specifically for Nest Labs
		#controllerdiskmode
		#controllerdriver
		#controllerfirmware
		#controllerreleasesupport
		#controlleronhcl
		#perfsvcstatus
		#hcldbuptodate
		
		$nCluster = Get-Cluster -Server $nVCSA | Where-object -Property Name -eq -Value $podConfig.vcsa.cluster
		Write-Log "Clearing VSAN Compatibility Checks - Nested Lab Support Only"
		Set-VSANSilentHealthChecks -Cluster $nCluster -Test controllerdiskmode,controllerdriver,controllerfirmware,controllerreleasesupport,controlleronhcl,perfsvcstatus,hcldbuptodate -Disable | Out-File -Append -LiteralPath $verboseLogFile

		# Enable vSphere HA on the Cluster
		$nCluster = Get-Cluster -Server $nVCSA | Where-object -Property Name -eq -Value $podConfig.vcsa.cluster
		if($nCluster.HAEnabled -eq $false) {
			Set-Cluster -Server $nVCSA -Cluster $podConfig.vcsa.cluster -HAEnabled $true -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
		} else {
			Write-Log "vSphere HA is already enabled on $($podConfig.vcsa.cluster), skipping" -Warning
		}
	} # End of if configureVSAN

	# Clear acknowledge Alarms
	Write-Log "Acknowledging any Alarms"
	$alarmMgr = Get-View AlarmManager -Server $nVCSA
	Get-Cluster -Server $nVCSA | Where-Object {$_.ExtensionData.TriggeredAlarmState} | ForEach-Object{
		$nCluster = $_
		$nCluster.ExtensionData.TriggeredAlarmState | ForEach-Object{
			$alarmMgr.AcknowledgeAlarm($_.Alarm,$nCluster.ExtensionData.MoRef)
		}
	}
	Close-VCSAConnection -vcsaName $podConfig.vcsa.ip
}

if($DeployNSXManager) {
	Write-Log "#### Deploying NSX Manager ####"
	$pVCSA = Get-VCSAConnection -vcsaName $podConfig.target.server -vcsaUser $podConfig.target.user -vcsaPassword $podConfig.target.password
	$pCluster = Get-Cluster -Name $podConfig.target.cluster -Server $pVCSA
	$pDatastore = Get-Datastore -Name $podConfig.target.datastore -Server $pVCSA
	$pPortGroup = Get-VDPortgroup -Name $podConfig.target.portgroup -Server $pVCSA
	$pFolder = Get-PodFolder -vcsaConnection $pVCSA -folderPath $podConfig.target.folder
	$pESXi = $pCluster | Get-VMHost -Server $pVCSA | where { $_.ConnectionState -eq "Connected" } | Get-Random
	$NSXhostname = "$($podConfig.nsx.name).$($podConfig.target.network.domain)"

	if((Get-VM -Server $pVCSA | Where-Object -Property Name -eq -Value $podConfig.nsx.name) -eq $null) {
		Write-Log "Deploying NSX Manager"
		#splat all the parameters
		$nsxManagerBuildParams = @{
			NsxManagerOVF           = $podConfig.sources.NSXAppliance
			Name                    = $podConfig.nsx.name
			ClusterName             = $pCluster
			ManagementPortGroupName = $pPortGroup
			DatastoreName           = $pDatastore
			FolderName              = $pFolder
			CliPassword             = $podConfig.nsx.password
			CliEnablePassword       = $podConfig.nsx.password
			Hostname                = $NSXhostname
			IpAddress               = $podConfig.nsx.ip
			Netmask                 = $podConfig.target.network.netmask
			Gateway                 = $podConfig.target.network.gateway
			DnsServer               = $podConfig.target.network.dns
			DnsDomain               = $podConfig.target.network.domain
			NtpServer               = $podConfig.target.network.ntp
			EnableSsh               = $true
			ManagerMemoryGB			= $podConfig.nsx.memory
		} # end $nsxManagerBuildParams
		try {
			New-NsxManager @nsxManagerBuildParams -StartVM -Wait -WarningAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile
			Write-Log "NSX Manager Deployed Successfully"
		}
		catch {
			Write-Log "An error occured during NSX Manager deployment" -Warning
		}
	} else {
		Write-Log "NSX manager exists, skipping" -Warning
	}
	Close-VCSAConnection -vcsaName $podConfig.target.server
}

if($configureNSX) {
	Write-Log "#### Configuring NSX Manager ####"
	$nVCSA = Get-VCSAConnection -vcsaName $podConfig.vcsa.ip -vcsaUser "administrator@$($podConfig.vcsa.sso.domain)" -vcsaPassword $podConfig.vcsa.sso.password
	$nCluster = Get-Cluster -Server $nVCSA -Name $podConfig.vcsa.cluster
	
	Write-Log "Connect NSX Manager to vCenter"
	$NSXServer = Connect-NSXServer -NsxServer $podConfig.nsx.ip -Username admin -Password $podConfig.nsx.password -DisableViAutoConnect -ViWarningAction Ignore -WarningAction SilentlyContinue |  Out-File -Append -LiteralPath $verboseLogFile
	Set-NsxManager -SyslogServer $podConfig.general.syslog -SyslogPort "514" -SyslogProtocol "UDP" | Out-File -Append -LiteralPath $verboseLogFile
	
	$NSXVC = Get-NsxManagerVcenterConfig
	if($NSXVC.Connected -ne $true) {
		Set-NsxManager -vcenterusername "administrator@$($podConfig.vcsa.sso.domain)" -vcenterpassword $podConfig.vcsa.sso.password -vcenterserver $podConfig.vcsa.ip |  Out-File -Append -LiteralPath $verboseLogFile
		Write-Log "Registered NSX Manager with VCSA $($podConfig.vcsa.ip)"
	} else {
		Write-Log "NSX Manager already connected to vCenter"
	}

	$NSXSSO = Get-NsxManagerSsoConfig
	if($NSXSSO.Connected -ne $true) {
		#Need to test for external PSC and use it not VCSA unless embedded
		if($podConfig.psc -ne $null) {
			# if $podConfig.psc -ne $null then our SSO Source will be the PSC and not the VCSA
		Set-NsxManager -ssousername "administrator@$($podConfig.vcsa.sso.domain)" -ssopassword $podConfig.vcsa.sso.password -ssoserver $podConfig.psc.ip |  Out-File -Append -LiteralPath $verboseLogFile
		Write-Log "NSX Manager connected to the Lookup Service at $($podConfig.psc.ip)"
		$pause = 10
	} else {
		# VCSA has embedded PSC Set SSO source to VCSA IP
		Set-NsxManager -ssousername "administrator@$($podConfig.vcsa.sso.domain)" -ssopassword $podConfig.vcsa.sso.password -ssoserver $podConfig.vcsa.ip |  Out-File -Append -LiteralPath $verboseLogFile
		Write-Log "NSX Manager connected to the Lookup Service at $($podConfig.vcsa.ip)"
		$pause = 10
		}
	} else {
		Write-Log "NSX Manager already connected to SSO"
		$pause = 1
	}
	Start-Sleep -Seconds $pause

	#Update the NSX Manager connection with SSO credentials
	# Write-Log "Refreshing connection to NSX Manager with SSO credentials"
	# $NSXServer = Disconnect-NSXServer -NsxServer $podConfig.nsx.ip -Username admin -Password $podConfig.nsx.password -WarningAction SilentlyContinue |  Out-File -Append -LiteralPath $verboseLogFile
	# $NSXServer = Connect-NSXServer -VCenterServer $podConfig.vcsa.ip -Username "administrator@$($podConfig.vcsa.sso.domain)" -Password $podConfig.vcsa.sso.password -ViWarningAction Ignore -DebugLogging -WarningAction SilentlyContinue |  Out-File -Append -LiteralPath $verboseLogFile
	
	Write-Log "Assigning Licensing NSX"
	$ServiceInstance = Get-View ServiceInstance -Server $nVCSA
	$LicenseManagerRef = Get-View $ServiceInstance.Content.licenseManager
	$LicenseAssignmentManager = Get-View $licenseManagerRef.licenseAssignmentManager
	try {
		$LicenseAssignmentManager.UpdateAssignedLicense("nsx-netsec",$podConfig.license.nsx,$NULL) | Out-File -Append -LiteralPath $verboseLogFile
	}
	catch {
		$ErrorMessage = $_.Exception.Message
		Write-Log $ErrorMessage -Warning
	}
	
	if((Get-NsxIpPool -Name "Controllers") -eq $null) {
		New-NsxIPPool -Name "Controllers" -Gateway $podConfig.target.network.gateway -SubnetPrefixLength $podConfig.target.network.prefix -StartAddress $podConfig.nsx.controller.startIp -EndAddress $podConfig.nsx.controller.endIp -DnsServer1 $podConfig.target.network.dns -DnsSuffix $podConfig.target.network.domain |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "NSX IP Pool exists, skipping" -Warning
	}

	if((Get-NSXController) -eq $null) {
		$NSXPool = Get-NSXIPPool "Controllers"
		$NSXPortGroup = Get-VDPortGroup -Name $podConfig.vcsa.portgroup -Server $nVCSA
		$NSXDatastore = Get-Datastore -Name "vsanDatastore" -Server $nVCSA
		Write-Log "Deploying NSX Controller - this may take a while as the OVF deploys"
		
		try {
			$NSXController = New-NsxController -Cluster $nCluster -datastore $NSXDatastore -PortGroup $NSXPortGroup -IpPool $NSXPool -Password $podConfig.nsx.controller.password -Confirm:$false -Wait
		}
		catch {
			Write-Log "Controller deployment failed" -Warning
		}
	} else {
		Write-Log "NSX Controller Exists, skipping" -Warning
	}

	Write-Log "## Preparing hosts ##"
	$clusterStatus = ($nCluster | Get-NsxClusterStatus | select -first 1).installed
	if($clusterStatus -eq "false") {
		Write-Log "Initiating installation of NSX agents"
		$nCluster | Install-NsxCluster | Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "Cluster is already installed" -Warning
	}

	Write-Log "Creating VTEP IP Pool"
	if((Get-NsxIpPool -Name "VTEPs") -eq $null) {
		New-NsxIPPool -Name "VTEPs" -Gateway $podConfig.target.network.gateway -SubnetPrefixLength $podConfig.target.network.prefix -StartAddress $podConfig.nsx.vtep.startIp -EndAddress $podConfig.nsx.vtep.endIp -DnsServer1 $podConfig.target.network.dns -DnsSuffix $podConfig.target.network.domain |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "VTEP IP Pool exists, skipping" -Warning
	}

	$nVDSwitch = Get-VDSwitch -Server $nVCSA -Name $podConfig.vcsa.distributedSwitch
	if((Get-NsxVdsContext) -eq $null) {
		Write-Log "Creating VDS Context"
		New-NsxVdsContext -VirtualDistributedSwitch $nVDSwitch -Teaming LOADBALANCE_SRCID -Mtu 1600 | Out-File -Append -LiteralPath $verboseLogFile
	}

	$vxlanStatus =  (Get-NsxClusterStatus $nCluster | where {$_.featureId -eq "com.vmware.vshield.vsm.vxlan" }).status | Out-File -Append -LiteralPath $verboseLogFile
	if($vxlanStatus -ne "GREEN") {
		# May need to add -VxlanPrepTimeout to New-NsxClusterVxlanConfig if experience any timeouts on cluster prep
		$nCluster | New-NsxClusterVxlanConfig -VirtualDistributedSwitch $nVDSwitch -ipPool (Get-NsxIpPool -Name "VTEPs") -VlanId 0 -VtepCount 2 -VxlanPrepTimeout 180 | Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "VXLAN already configured, skipping" -Warning
	}

	# Change the NSX VXLAN UDP Port to enable nested ESXi, if you have NSX enabled on the
	# VDSwitch that hosts the nested environment, then you must change the port to something
	# that is different.
	Write-Log "Setting VXLAN UDP Port 8472"
	Invoke-NsxRestMethod -Method PUT -URI "/api/2.0/vdn/config/vxlan/udp/port/8472" | Out-File -Append -LiteralPath $verboseLogFile

	Write-Log "## Creating Transport Zone ##"
	if((Get-NsxTransportZone -Name "TZ") -eq $null) {
		New-NSXTransportZone -Name "TZ" -Cluster $nCluster -ControlPlaneMode "UNICAST_MODE" | Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "Transport Zone exists, skipping" -warning
	}

	Close-VCSAConnection -vcsaName $podConfig.vcsa.ip
}

# if($deployvRAAppliance) {
# 	Write-Log "Deploying vRealize Automation Appliance"
# 	$ovfConfig = Get-ovfConfiguration $vRAAppliance
# 	$ovfConfig.NetworkMapping.Network_1.value = $Network
# 	$ovfConfig.IpAssignment.IpProtocol.value = "IPv4"
# 	$ovfConfig.vami.VMware_vRealize_Appliance.ip0.value = $vRAAppIpAddress
# 	$ovfConfig.vami.VMware_vRealize_Appliance.netmask0.value = $podConfig.target.network.netmask
# 	$ovfConfig.vami.VMware_vRealize_Appliance.gateway.value = $podConfig.target.network.gateway
# 	$ovfConfig.vami.VMware_vRealize_Appliance.DNS.value = $podConfig.target.network.dns
# 	$ovfConfig.vami.VMware_vRealize_Appliance.domain.value  = $podConfig.target.network.domain
# 	$ovfConfig.vami.VMware_vRealize_Appliance.searchpath.value = $podConfig.target.network.domain
# 	$ovfConfig.common.varoot_password.value = $podConfig.general.password
# 	$ovfConfig.common.va_ssh_enabled.value = $podConfig.general.ssh
# 	$vRAVM = Import-VApp -Server $vCenter -VMHost $pEsxi -Source $vRAAppliance -ovfConfiguration $ovfConfig -Name $vRAAppName -Location $cluster -Datastore $datastore -DiskStorageFormat thin
# 	Write-Log "Moving $vRAAppName to $VMFolder"
# 	$vm = Get-VM -Name $vRAAppName
# 	$vm | Move-VM -Destination $folder | Out-File -Append -LiteralPath $verboseLogFile
# 	Write-Log "Powering on $vRAAppName"
# 	Start-VM -Server $vCenter -VM $vm -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
# }

# Verify any connection to $defaultVIServer is closed
Close-VCSAConnection

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes,2)

# Write-Log "Pod Deployment Completed in $($duration) minutes"
Write-Log "Pod Deployment Complete!"
Write-Log "StartTime: $StartTime"
Write-Log "  EndTime: $EndTime"
Write-Log " Duration: $duration minutes"
Write-Host -ForegroundColor Magenta "`nFatPacket Labs - Where Rebuilds Happen`n"