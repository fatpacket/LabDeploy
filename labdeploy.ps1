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

if($PSBoundParameters.Count -eq 1) {
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



###################################################################################################################
##                                   Common Cross-Application Functions                                          ##
###################################################################################################################


function Write-Log {
	param(
		[Parameter(Mandatory=$true)]
		[String]$Message,
		[switch]$Warning = $false,
		[switch]$Info = $false
	)

    $Timestamp = Get-Date -UFormat "%m-%d-%Y %H:%M:%S"
	Write-Host -NoNewline -ForegroundColor White "[$timestamp]"

    if($Warning){
		Write-Host -ForegroundColor Yellow " WARNING: $message"
	} elseif($Info) {
		Write-Host -ForegroundColor White " $message"
	}else {
		Write-Host -ForegroundColor Green " $message"
	}
    $logMessage = "[$timeStamp] $message"
    $logMessage | Out-File -Append -LiteralPath $verboseLogFile
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
        return $existingConnection
    } else {
        $connection = Connect-VIServer -Server $vcsaName -User $vcsaUser -Password $vcsaPassword -WarningAction SilentlyContinue
        return $connection
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


function ConvertJSONToHash {
# URL: https://stackoverflow.com/questions/22002748/hashtables-from-convertfrom-json-have-different-type-from-powershells-built-in-h
param(
        $root
    )
    $hash = @{}

    $keys = $root | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name

    $keys | ForEach-Object {
        $key=$_
        $obj=$root.$($_)
        if($obj -match "@{")
        {
            $nesthash=ConvertJSONToHash $obj
            $hash.add($key,$nesthash)
        }
        else
        {
           $hash.add($key,$obj)
        }

    }
    return $hash
}


function ConvertPSObjectToHashtable {
# URL: https://stackoverflow.com/questions/22002748/hashtables-from-convertfrom-json-have-different-type-from-powershells-built-in-h
param (
        [Parameter(ValueFromPipeline)]
        $InputObject
    )

    process
    {
        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string])
        {
            $collection = @(
                foreach ($object in $InputObject) { ConvertPSObjectToHashtable $object }
            )

            Write-Output -NoEnumerate $collection
        }
        elseif ($InputObject -is [psobject])
        {
            $hash = @{}

            foreach ($property in $InputObject.PSObject.Properties)
            {
                $hash[$property.Name] = ConvertPSObjectToHashtable $property.Value
            }

            $hash
        }
        else
        {
            $InputObject
        }
    }
}





###################################################################################################################
##                                       Script Specific Functions                                               ##
###################################################################################################################

Function Install-SoftwareLicense {
	<#
    .NOTES
        ===========================================================================
        Created by:    Luis Chanu
        Organization:  On Site Network Solutions, Inc.
        Twitter:       @LuisChanu
        ===========================================================================
    .DESCRIPTION
        This function installs the software license(s) for a given product into a target Server.
        It returns:
                $null if the LicenseFile does not exist
                Integer equating to the number of matching licenses within LicenseFile
    .PARAMETER Server
        The name of Server where the licenses are being installed
    .PARAMETER Vendor
        The name of the Vendor whose licenses are being installed
    .PARAMETER Product
        The name of the Product whose licenses are being installed.  If not provided, all Vendor's products are matched.
    .PARAMETER Version
        The version number for the Products you want to install licenses for
    .PARAMETER LicenseFile
        The name of the License File containing the licenses.  If not specified, ".\LicenseData.json" will be used
    .EXAMPLE
        Install-SoftwareLicense -Server VIServer -Vendor VMware -Product vCenter
    .EXAMPLE
        Install-SoftwareLicense -Server VIServer -Vendor VMware -Product vSphere -LicenseFile "MyLicenseFile.json"
	#>
	param(
        [Parameter(Mandatory=$true)]$Server,
        [Parameter(Mandatory=$true)][String[]]$Vendor,
        [String[]]$Product = $null,
        [String[]]$Version = $null,
        [String[]]$LicenseFile = ".\LicenseData.json"
    )

    # Verify LicenseFile exists
    If (Test-Path -Path $LicenseFile -PathType Leaf) {
        Write-Log "Using $LicenseFile as license source for $Vendor $Product"
    }
    else {
        Write-Log "Unable to locate LicenseFile $LicenseFile" -Warning
        return $null
    }

    # Import JSON LicenseFile
    $JSONLicenseData = (Get-Content $($LicenseFile) -Raw) | ConvertFrom-Json

    # Convert JSON LicenseData to a usable PowerShell Hash Table
    $LicenseData  = $JSONLicenseData | ConvertPSObjectToHashTable


    ##############################################################
    ##   Determine which licenses match the criteria provided   ##
    ##############################################################

    # Document array variable which will hold the licenses that need to be installed.  Elements of the array will be
    # the License HashTable from the LicenseData data structure.
    $LicensesToInstall = @()

    # Walk the data structure, looking for matches
    ForEach ($LicenseVendor in $LicenseData.Keys) {
		# If Vendor doesn't match, no bother checking its licenses...go on to next vendor
		If ($LicenseVendor  -ne $Vendor)  { Continue }
		$LicenseProducts = $LicenseData[$LicenseVendor]

		ForEach ($LicenseProduct in $LicenseProducts.Keys) {
			# If Prodocut doesn't match, no bother checking its licenses...go on to next product
			If ($LicenseProduct -ne $Product) { Continue }

			ForEach ($License in $LicenseProducts[$LicenseProduct].Licenses) {
                # If $Version is supplied by user does NOT match, then Continue to next iteration of loop
                If (($Version -ne $null) -and (-not ($Version -match $LicenseProducts[$LicenseProduct].Version))) {
                    Continue
                }

                # If we reach this point, then we have a matching license...so, add it to the $LicensesToInstall array
                $LicensesToInstall += $License
            }
        }
    }


    #########################################
    ##  Install Licenses To Target Server  ##
    #########################################

    # Depending on the platform, perform the appropriate license install procedure
    switch ($Vendor)
        {
            "VMware" {
                    Write-Log "Licensing $Vendor $Product"
                    Write-Log "Total of $($LicensesToInstall.Count) license(s) found"

                    # Get vCenter Server instance
                    $serviceInstance   = Get-View ServiceInstance -Server $Server
                    $licenseManagerRef = $serviceInstance.Content.LicenseManager
                    $licenseManager    = Get-View $licenseManagerRef

                    # Add each license to License Manager
                    ForEach ($License in $LicensesToInstall) {
						Write-Log "Adding $($License.Quantity) $($License.Measure) license for $Product $($License.Edition)"
                        $licenseManager.AddLicense($License.KeyCode,$null) |  Out-File -Append -LiteralPath $verboseLogFile
                    }

					# Do not attempt to match with other Switch blocks
                    break
            }

            Default {
                    Write-Log "Licensing of $Vendor not yet supported.  No $Product licenses installed" -Warning
            }
        }

	# Slight Pause to see if that resolves the issue with NSX licenses
	Start-Sleep 10

	# Return number of Licenses Installed
    return $LicensesToInstall.Count
}


Function Assign-SoftwareLicense {
	<#
    .NOTES
        ===========================================================================
        Created by:    Luis Chanu
        Organization:  On Site Network Solutions, Inc.
        Twitter:       @LuisChanu
        ===========================================================================
    .DESCRIPTION
		This function queries the Server for an available license from a given Product, and assigns it to the
		Asset (i.e. vSphere Host, vSAN Cluster, etc.), depending on the type of Product is being licensed.
        It returns:
				$null  if an error in assigning a license to the Asset
				$false if no license was applied because the Asset was already licensed
				$true  if the Asset was assigned a license
    .PARAMETER Server
        The of Server where the licenses are located (VIServer object, NOT the name)
    .PARAMETER Vendor
        The name of the Vendor who created the licenses
    .PARAMETER Product
        The name of the Product is used to match licenses to assign
    .PARAMETER Version
        The Version number for the licenses you want to use
    .PARAMETER Asset
        The name of the Asset to which the licenses are being assign.  Asset depends on the Product being licensed.
    .EXAMPLE
        Assign-SoftwareLicense -Server VIServer -Vendor VMware -Product vCenter
    .EXAMPLE
        Assign-SoftwareLicense -Server VIServer -Vendor VMware -Product vSphere -Asset "10.1.2.3"
	#>
	param(
        [Parameter(Mandatory=$true)]$Server,
		[Parameter(Mandatory=$true)][String[]]$Vendor,
        [String[]]$Product = $null,
        [String[]]$Version = $null,
		[String[]]$Asset   = $null
		)

	# Decoded License EditionKey value Hash Table
	$EditionKeyTable = @{
		"vCenter" = "vc"	# vc.standard.instance
		"vSphere" = "esx"	# esx.enterprisePlus.cpuPackage
		"vSAN"    = "vsan"	# vsan.enterprise2
		"NSXv"	  = "nsx"	# nsx.vsphere.vm
	}

	# Depending on the platform, perform the appropriate license install procedure
	switch ($Vendor)
		{
			"VMware" {
					# Get vCenter Server instance
					$serviceInstance   = Get-View ServiceInstance -Server $Server
					$licenseManagerRef = $serviceInstance.Content.LicenseManager
					$licenseManager    = Get-View $licenseManagerRef

					# Get Licenses installed on License Manager
					$Licenses = $LicenseManager.Licenses

					# Iterate through each License
					ForEach ($License in $Licenses) {
						$LicenseKey  = $License.LicenseKey
						$LicenseType = $LicenseManager.DecodeLicense($LicenseKey)

						# If License does not match product, then continue to next License
						If (-not ($LicenseType.EditionKey -match $EditionKeyTable[$Product])) {
							Continue
						}

						# If License has no available licenses left, then continue to next License
						If (($License.Total - $License.Used) -eq 0) {
							Continue
						}

						# At this point, License is for the given Product, and is not entirely consumed, so try to assign
						$licenseAssignmentManager = Get-View $licenseManager.LicenseAssignmentManager

						# Product Specific assignment code below
						switch($Product)
							{
								"vCenter" {
										# Get the current license, if any, assigned to the vCenter Server
										$QueriedLicense = $licenseAssignmentManager.QueryAssignedLicenses($Server.InstanceUuid)

										# Check if the License is a vCenter Permanent License
										If ($QueriedLicense.AssignedLicense.LicenseKey -ne "00000-00000-00000-00000-00000") {
											# Server already licensed, so exit
											return $false
										}

										Write-Log "Assigning vCenter Server License"
										try {
											$licenseAssignmentManager.UpdateAssignedLicense($Server.InstanceUuid, $LicenseKey, $null) | Out-File -Append -LiteralPath $verboseLogFile
										}
										catch {
											$ErrorMessage = $_.Exception.Message
											Write-Log $ErrorMessage -Warning
										}
										# License applied, so we don't need to keep going
										return $true
								}

								"vSphere" {
										# Verify vSphere Host information provided, as it's required
										If ($Asset -eq $null) {
											Write-Log "Unable to assign vSphere License, as ESXi host information was not provided" -Warning

											# Without ESXi host info, can't do anything, so return from function
											return $null
										}

										# If VMHost already has a permanent license, exit
										If ((Get-VMHost $Asset).LicenseKey -ne "00000-00000-00000-00000-00000") {
											# VMHost already licensed
											Write-Log "ESXi host $Asset already licensed"

											# Return from function so that we can check the next Asset
											return $false
										}

										# Get number of sockets in the vSphere host
										$VMHostCPUCount = (Get-VMHost $Asset | Get-View).Hardware.CpuInfo.NumCpuPackages

										# If we do NOT have sufficient capacity, then continue to next license
										If (($License.Total-$License.Used) -lt $VMHostCPUCount) {
											Continue
										}

										# At his point, we have sufficient capcity, so assign the license to the host

										# Save current "ConnectionState"
										$VMHost = Get-VMHost $Asset

										# If needed, place VMHost into Maintenance Mode
										If ($VMHost.ConnectionState -ne "Maintenance") {
											Write-Log "Placing ESXi host $Asset into Maintenance Mode"
											$VMHost | Set-VMHost -State Maintenance | Out-File -Append -LiteralPath $verboseLogFile
										}

										# Assign License to VMHost
										Write-Log "Assigning License Key to ESXi host $Asset"
										$VMHost | Set-VMHost -LicenseKey $LicenseKey | Out-File -Append -LiteralPath $verboseLogFile

										# Restore VMHost to original ConnectionState
										Write-Log "Returning ESXi host $Asset to $($VMHost.ConnectionState)"
										$VMHost | Set-VMHost -State $VMHost.ConnectionState | Out-File -Append -LiteralPath $verboseLogFile

										# License applied, job done, so return from function
										return $true
								}

								"vSAN" {
										# Verify vSAN Cluster information provided, as it's required
										If ($Asset -eq $null) {
											Write-Log "Unable to assign vSAN License, as vSAN Cluster information was not provided" -Warning

											# Without vSAN Cluster info, can't do anything, so return from function
											return $null
										}

										# See if vSAN Cluster is already licensed by seeing by first getting the Cluster Entity ID (MoRef),
										# Then query the License Manager to obtain all of the licenses associated with the Entity ID.
										$ClusterRef = (Get-Cluster -Server $Server -Name $Asset | get-view).MoRef
										$ClusterLicenses = $licenseAssignmentManager.QueryAssignedLicenses($ClusterRef.value)

										# See if any of the licenses returned are Permanent vSAN Licenses
										##--> Note: May not need the loop as only 1 license should ever be returned, but QueryAssignedLicense does return an Array.
										ForEach ($ClusterLicense in $ClusterLicenses) {
											# If vSAN the license is a vSAN Permanent license, then it's already licensed, so exit
											If ($ClusterLicense.AssignedLicense.LicenseKey -ne "00000-00000-00000-00000-00000") {
												# vSAN cluster already licensed, so exit
												return $false
											}
										}

										# At this point, there is no vSAN permanent license assigned to the cluster, so we need to assign one

										# Get the Cluster object so we can see all the hosts in the cluster
										$Cluster = (Get-Cluster -Server $Server -Name $Asset)

										# Go through all the VMHosts in the cluster, and add up their CPUs
										$TotalCPUs = 0
										$Cluster | Get-VMHost | ForEach-Object {$TotalCPUs += $_.NumCpu}

										# If License does NOT have sufficient capacity left, continue to next License
										If (($License.Total - $License.Used) -lt $TotalCPUs) {
											Continue
										}

										# At this point, we have a vSAN license with sufficient capacity, so let's assign it
										Write-Log "Assigning vSAN License to Cluster $Cluster"
										try {
											$licenseAssignmentManager.UpdateAssignedLicense(($ClusterRef.value), $LicenseKey, $null) | Out-File -Append -LiteralPath $verboseLogFile
										}
										catch {
											$ErrorMessage = $_.Exception.Message
											Write-Log $ErrorMessage -Warning
										}

										# License Assigned, so exit
										return $true
								}

								"NSXv" {
										Write-Log "Assigning NSX-v License"
										try {
											$licenseAssignmentManager.UpdateAssignedLicense("nsx-netsec", $LicenseKey, $null) #----------------------- | Out-File -Append -LiteralPath $verboseLogFile
										}
										catch {
											$ErrorMessage = $_.Exception.Message
											Write-Log $ErrorMessage -Warning
										}
										# License applied, job done, so return from function
										return $true
								}

								default {
										Write-Log "Licensing of $Product not yet supported." -Warning
										# No license applied
										return $false
								}
							} # Close Product Block
					} # Close ForEach License
			} # Close Vendor=VMware

			default {
				Write-Log "Licensing of $Vendor not yet supported." -Warning
				# No License applied
				return $false
			}
		} # Close Vendor Block
}


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


function Get-SoftwarePath {
    <#
    .NOTES
        ===========================================================================
        Created by:    Luis Chanu
        Organization:  On Site Network Solutions, Inc.
        Twitter:       @LuisChanu
        ===========================================================================
    .DESCRIPTION
        This function returns the path to the software installtion option or patch for the supplied matching critera.
		It returns:
                exit if Software repository file cannot be found
                $null if there are no matching options.
                Path of the matching software installation option, or the patch, depending on what is requested.
    .PARAMETER Vendor
        The name of the software Vendor.  This field is required.  If there is no match, the application exits.
    .PARAMETER Product
        The name of the Software Product.  This field is required.  If there is no match, the application exists.
    .PARAMETER Version
		The version number for the software Product you want to install.  If the Version field is not
		provided (i.e. set to $null), then a menu is displaying all versions of the given Vendor's Software
		product.
    .PARAMETER Patch
        If this optional switch is set, then it returns not an installation option, but a patch
    .PARAMETER MatchVersionUsingRegEx
		When set to $true, if a Version number is provided, it will be  matched to the software options using
		Regular Expressions.  This allows regular expressions to be placed within the configuration
		files, if so desired.
    .PARAMETER File
        Name of the File containing all of the the software products which can be installed.  If not
        specified, ".\Software.json" will be used
    .EXAMPLE
        Get-SoftwarePath -Vendor "VMware" -Product "vCenter" -Version "6.5.0U1C"
    .EXAMPLE
        Get-SoftwarePath -Vendor "VMware" -Product "ESXi" -Version "6.5.0U1"
    .EXAMPLE
        Get-SoftwarePath -Vendor "VMware" -Product "ESXi" -Version "ESXi650-201710001" -Patch
    .EXAMPLE
        Get-SoftwarePath -Vendor "VMware" -Product "ESXi" -File ".\MySoftwareList.json"
	#>
    param(
        [Parameter(Mandatory=$true)][String]$Vendor,
        [Parameter(Mandatory=$true)][String]$Product,
        [switch]$Patch    			  = $false,
		[bool]$MatchVersionUsingRegEx = $false,
		[String]$Version 			  = $null,
        [String]$File     			  = ".\Software.JSON"
    )

    # Verify Software File exists
    If (Test-Path -Path $File -PathType Leaf) {
        Write-Log "Using $File as software repsotory configuration file for $Vendor $Product"
    }
    else {
        Write-Log "Unable to locate Software Repository configuration file $File... Exiting." -Warning
        exit
    }

    # Import JSON Software Repository Information
    $JSONSoftware = (Get-Content $($File) -Raw) | ConvertFrom-Json

    # Convert JSON Software Repository Data to a usable PowerShell Hash Table
    $Software  = $JSONSoftware | ConvertPSObjectToHashTable

    #################################################################
    ##   Determine if any software matches the criteria provided   ##
    #################################################################

	# If either Vendor or Product is $null, return $null, send warning and return as we would never have a match
	If (($Vendor -eq $null) -or ($Product -eq $null)) {
		Write-Log "Unable to search Software repository, as either Vendor or Product was not provided as required." -Warning
		return $null
	}

    # Document array variable which will hold the matching software options.  Elements of the array will be
    # the Software HashTable from the Software repository data structure.
    $MatchingOptions = @()

    # Walk through each of the vendors in the software repository
    ForEach ($SoftwareVendor in $Software.Keys) {
        # If this vendor is not the vendor we're looking for, keep looking
        If ($SoftwareVendor  -ne $Vendor)  { Continue }

        # Walk through each of the products for the vendor
        $SoftwareProducts = $Software[$SoftwareVendor]
        ForEach ($SoftwareProduct in $SoftwareProducts.Keys) {
            # If this software product is not the product we're looking for, keep looking
            If ($SoftwareProduct -ne $Product) { Continue }

            # Check to see if the user wants to check for patches or software installers, as that
            # will drive what options we check.
            If ($Patch -eq $true) {
                $Options = $SoftwareProducts[$SoftwareProduct].Patches
            }
            else {
                $Options = $SoftwareProducts[$SoftwareProduct].Installers
            }

            # Walk through each of the Installation Options that exist for this product
            ForEach ($Option in $Options) {

				# If no Version provided by the user, match all versions
				If (($Version -eq $null) -or ($Version -eq "")) {
					$MatchingOptions += $Option
					Continue
				}

				# If we are matching using Regular Expressions, use Match to see if RegEx match
				If ($MatchVersionUsingRegEx -eq $true) {
					# If we do not match against RegEx, get next Option to check
					If ($Option.Version -notmatch $Version) {
						Continue
					}
				}
				# Since we're not using RegEx, if we don't match EXACTLY, get next Option to check
				elseif ($Option.Version -ne $Version) {
					Continue
				}

	            # If we reach this point, then we have a matching software option...so, add it to the array
    	        $MatchingOptions += $Option
            }
        }
    }

    ############################################################
    #   At this point, we have all of the matching options.   ##
    ############################################################

    # If we have 0 matching options, return $null
    If ($MatchingOptions.Count -eq 0) {
        Write-Log "No matching software options for $Vendor $Product $Version" -Warning
        return $null
    }

    # If only one (1) object matched, that's the SelectedOption
    If ($MatchingOptions.Count -eq 1) {
        $SelectedOption = $MatchingOptions[0]
    }
    else {
        $Splat = @{
            DialogBoxTitle  = "$Vendor $Product Options"
            DialogBoxPrompt = "Please select one of the versions below:"
            ItemList        = $MatchingOptions
        }
        Write-Log "Multiple software options for $Vendor $Product.  Prompting user to select one."
        $SelectedOption = Select-ItemFromList @Splat
    }

    ####################################################################
    #   At this point, it should be narrowed down to 0 or 1 objects   ##
    ####################################################################

    # If user did not select any options (i.e. Cancelled), return $null
    If ($SelectedOption -eq $null) {
        Write-Log "User did not select an option for $Vendor $Product." -Warning
        return $null
    }

    # If Selected Option does not include a file, return the directory
    If ($SelectedOption.File -eq $null) {
        $FullPath = $SelectedOption.Directory
    }
    else {
        $FullPath = "$($SelectedOption.Directory)\$($SelectedOption.File)"
    }

    # Return location of requested softare product
    Write-Log "$Vendor $Product $Version is located at $FullPath"

    # If FullPath (which can be either a directory or file) does not exist, warn user
    If (-not (Test-Path -Path $FullPath)) {
		# If Selection is a Directory
		If ($SelectedOption.File -eq $null) {
			Write-Log "$Vendor $Product $Version installation directory $FullPath does not exist." -Warning
		}
		# ...Otherwise, Selection path ends with a file
		else {
			Write-Log "$Vendor $Product $Version installation file $FullPath does not exist." -Warning
		}
    }

	return $FullPath
}


function Select-ItemFromList {
    param(
        [Parameter(Mandatory=$True)]
        [String]$DialogBoxTitle,
        [Parameter(Mandatory=$True)]
        [String]$DialogBoxPrompt,
        [Parameter(Mandatory=$True)]
        [Array]$ItemList
    )

    # Working Script:   https://docs.microsoft.com/en-us/powershell/scripting/getting-started/cookbooks/selecting-items-from-a-list-box?view=powershell-5.1

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $DialogBoxTitle
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = "CenterScreen"

    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(75,120)
    $OKButton.Size = New-Object System.Drawing.Size(75,23)
    $OKButton.Text = "OK"
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(150,120)
    $CancelButton.Size = New-Object System.Drawing.Size(75,23)
    $CancelButton.Text = "Cancel"
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.Text = $DialogBoxPrompt
    $form.Controls.Add($label)

    $ListBox = New-Object System.Windows.Forms.ListBox
    $ListBox.Location = New-Object System.Drawing.Point(10,40)
    $ListBox.Size = New-Object System.Drawing.Size(260,20)
    $ListBox.Height = 80

    # Sort the ListBox entries so the item list displays in order
    $ListBox.Sorted = $true

    # Add the various choices to choose from to the Listbox
    $ItemList.GetEnumerator() | ForEach-Object {
        [void] $ListBox.Items.Add($_.Name)
    }

    $form.Controls.Add($ListBox)

    $form.Topmost = $True

    $result = $form.ShowDialog()

    # If user pressed OK, see what they selected
    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
    {
        $Selection = $ListBox.SelectedItem

        # Iterate through the ItemList to see which item the user selected, and return it
        $ItemList.GetEnumerator() | ForEach-Object {
            if ($_.Name -eq $Selection)
            {
                return $_
            }
        }
    }
    else
    {
        # If OK wasn't selected, then return Null
        $Selection = $null
    }
}







###################################################################################################################
##                                      Script Begins Execution Here                                             ##
###################################################################################################################

# Start the stopwatch
$StartTime = Get-Date

# Import the JSON Config File
$podConfig = (get-content $($configFile) -Raw) | ConvertFrom-Json

# Log File
$DateTime = Get-Date -UFormat "%Y%m%d_%H%M%S"
$verboseLogFile = ".\Logs\LabDeploy_POD-$($podConfig.Pod)_$DateTime.LOG"

# Header
Write-Host -ForegroundColor Magenta "`nFatPacket Labs - Where Rebuilds Happen`n"


#########################################################
##  Obtain Paths To Software Versions Being Installed  ##
#########################################################

# Verify VCSA was defined in the configuration file
If ([bool]$podConfig.Software.VCSA) {
	$VCSAInstaller = Get-SoftwarePath -Vendor $podConfig.Software.VCSA.Vendor  -Product $podConfig.Software.VCSA.Product -Version $podConfig.Software.VCSA.Version -MatchVersionUsingRegEx $podConfig.Software.VCSA.MatchVersionUsingRegEx

	# If no match was found for the software, create a warning message
	If ($VCSAInstaller -eq $null) {
		Write-Log "No matching entry found in the Software repository for VCSA" -Warning
	}
}
else {
	# Software entry not defined in configuration file
	Write-Log "Configuration file does not contain entry for Sofware.VCSA" -Info
}


# Verify ESXi was defined in the configuration file
If ([bool]$podConfig.Software.ESXi) {
	# Check to see if the entry is for patches
	If ($podConfig.Software.ESXi.Patch -eq $true) {
		$ESXi65aBundle = Get-SoftwarePath -Vendor $podConfig.Software.ESXi.Vendor -Product $podConfig.Software.ESXi.Product -Version $podConfig.Software.ESXi.Version -MatchVersionUsingRegEx $podConfig.Software.ESXi.MatchVersionUsingRegEx -Patch
	}
	else {
		# We're installing, and not patching, so set ESXi patching variable to $null
		$ESXi65aBundle = $null

		# Get path to the installer
		$ESXiAppliance = Get-SoftwarePath -Vendor $podConfig.Software.ESXi.Vendor  -Product $podConfig.Software.ESXi.Product -Version $podConfig.Software.ESXi.Version -MatchVersionUsingRegEx $podConfig.Software.ESXi.MatchVersionUsingRegEx

		# If no match was found for the software, create a warning message
		If ($ESXiAppliance -eq $null) {
			Write-Log "No matching entry found in the Software repository for ESXi" -Warning
		}
	}
}
else {
	# Software entry not defined in configuration file
	Write-Log "Configuration file does not contain entry for Sofware.ESXi" -Info
}


# Verify NSXv was defined in the configuration file
If ([bool]$podConfig.Software.NSXv) {
	$NSXAppliance = Get-SoftwarePath -Vendor $podConfig.Software.NSXv.Vendor -Product $podConfig.Software.NSXv.Product -Version $podConfig.Software.NSXv.Version -MatchVersionUsingRegEx $podConfig.Software.NSXv.MatchVersionUsingRegEx

	# If no match was found for the software, create a warning message
	If ($NSXAppliance -eq $null) {
		Write-Log "No matching entry found in the Software repository for NSXv" -Warning
	}
}
else {
	# Software entry not defined in configuration file
	Write-Log "Configuration file does not contain entry for Sofware.NSXv" -Info
}


# Verify vRA was defined in the configuration file
If ([bool]$podConfig.Software.vRA) {
	$vRAAppliance = Get-SoftwarePath -Vendor $podConfig.Software.vRA.Vendor -Product $podConfig.Software.vRA.Product -Version $podConfig.Software.vRA.Version -MatchVersionUsingRegEx $podConfig.Software.vRA.MatchVersionUsingRegEx

	# If no match was found for the software, create a warning message
	If ($vRAAppliance -eq $null) {
		Write-Log "No matching entry found in the Software repository for vRA" -Warning
	}
}
else {
	# Software entry not defined in configuration file
	Write-Log "Configuration file does not contain entry for Sofware.vRA" -Info
}



<#-------------Previous config -- can delete once new code is working
$VCSAInstaller  = "$($podConfig.sources.VCSAInstaller)"
$ESXiAppliance  = "$($podConfig.sources.ESXiAppliance)"
$NSXAppliance   = "$($podConfig.sources.NSXAppliance)"
#$vRAAppliance   = "$($podConfig.sources.vRAAppliance)"
#$ESXi65aBundle	= "$($podConfig.sources.ESXiPatch)"
#>


#################################################
##   Script "Heavy Lifting" Work Begins Here   ##
#################################################

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

	# Use .Net System.Collections.ArrayList object over regular Array for additional Remove and Clear methods
	$deployTasks = New-Object System.Collections.ArrayList

	$podConfig.esxi.hosts | ForEach-Object {
		Write-Log "Selecting a host from $($podConfig.target.cluster)"
		$pESXi = $pCluster | Get-VMHost -Server $pVCSA | Where-Object { $_.ConnectionState -eq "Connected" } | Get-Random
		Write-Log "$($pESXi) selected."

		$nestedESXiName = $_.name
		$nestedESXiIPAddress = $_.ip

		if((Get-VM | Where-Object -Property Name -eq -Value $nestedESXiName) -eq $null) {
			$ovfConfig = Get-ovfConfiguration -Ovf $ESXiAppliance
			$ovfConfig.Common.guestinfo.hostname.Value   = $nestedESXiName
			$ovfConfig.Common.guestinfo.ipaddress.Value  = $nestedESXiIPAddress
			$ovfConfig.Common.guestinfo.netmask.Value    = $podConfig.target.network.netmask
			$ovfConfig.Common.guestinfo.gateway.Value    = $podConfig.target.network.gateway
			$ovfConfig.Common.guestinfo.dns.Value        = $podConfig.target.network.dns
			$ovfConfig.Common.guestinfo.domain.Value     = $podConfig.target.network.domain
			$ovfConfig.Common.guestinfo.ntp.Value        = $podConfig.target.network.ntp
			$ovfConfig.Common.guestinfo.syslog.Value     = $podConfig.general.syslog
			$ovfConfig.Common.guestinfo.password.Value   = $podConfig.general.password
			$ovfConfig.Common.guestinfo.ssh.Value        = $podConfig.general.ssh
			$ovfConfig.Common.guestinfo.createvmfs.Value = $podConfig.esxi.createVMFS
			$ovfConfig.NetworkMapping.VM_Network.Value   = $pPortGroup

			Write-Log "Deploying Nested ESXi VM $($nestedESXiName)"
			$task = Import-VApp -Server $pVCSA -VMHost $pESXi -Source $ESXiAppliance -ovfConfiguration $ovfConfig -Name $nestedESXiName -Location $pCluster -Datastore $pDatastore -InventoryLocation $pFolder -DiskStorageFormat thin -RunAsync -ErrorAction SilentlyContinue
			$deployTasks.Add($task) | Out-Null
		} else {
			Write-Log "Nested ESXi host $($nestedESXiName) exists, skipping" -Warning
		}
	}

	# Use .Net System.Collections.ArrayList object over regular Array for additional Remove and Clear methods
	$RevisedTaskList = New-Object System.Collections.ArrayList
	$CompletedTasks  = New-Object System.Collections.ArrayList
	$taskCount       = $deployTasks.Count

	while($taskCount -gt 0) {
		Write-Log "Task count $($taskCount)"
		$CompletedTasks.Clear()
		$deployTasks | ForEach-Object {
			Write-Log -Message "`t- Task $($_.Id) - $($_.State) - $($_.PercentComplete)%"
			if($_.State -eq "Success") {
				# Deployment Completed
				Write-Log "Deployment task $($_.Id) ($($_.Result)) succeeded, configuring"

				$nestedESXiVM = Get-VM -Name $_.Result -Server $pVCSA

				Write-Log "Updating vCPU Count to $($podConfig.esxi.cpu), Cores Per Socket to $($podConfig.esxi.coresPerSocket), & vMEM to $($podConfig.esxi.ram) GB"
				$nestedESXiVM | Set-VM -NumCpu $podConfig.esxi.cpu -CoresPerSocket $podConfig.esxi.coresPerSocket -MemoryGB $podConfig.esxi.ram -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

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

				Write-Log "Powering On $($_.Result)"
				Start-VM -VM $nestedESXiVM -Confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile

				# Add this Task to the completed list
				$CompletedTasks.Add($_) | Out-Null

			} elseif($_.State -eq "Error") {
				Write-Log -Message " failed to deploy" -Warning

				# Even though it errored out, task is completed, so add it to the completed tasks list
				$CompletedTasks.Add($_) | Out-Null
			}
		}
		# If we have any CompletedTasks, remove them from the list of all the tasks being deployed
		If ($CompletedTasks.Count -gt 0) {
			$RevisedTaskList = $deployTasks
			$CompletedTasks | ForEach-Object {
				$RevisedTaskList.Remove($_)
				$taskCount--
			}
			$deployTasks = $RevisedTaskList
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
			if((Get-VM | Where-Object {$_.name -eq $podConfig.psc.name}) -eq $null) {
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
			if((Get-VM | Where-Object	 {$_.name -eq $podConfig.vcsa.name}) -eq $null) {
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
		Install-SoftwareLicense -Server $nVCSA -Vendor VMware -Product vCenter | Out-Null
		Install-SoftwareLicense -Server $nVCSA -Vendor VMware -Product vSphere | Out-Null
		Install-SoftwareLicense -Server $nVCSA -Vendor VMware -Product vSAN    | Out-Null

		Assign-SoftwareLicense  -Server $nVCSA -Vendor VMware -Product vCenter | Out-Null
	}

	if($configureHosts) {
		Write-Log "## Adding hosts to cluster ##"
		$nCluster = Get-Cluster -Name $podConfig.vcsa.cluster -Server $nVCSA
		$podConfig.esxi.hosts | ForEach-Object {
			$nestedESXiName = $_.name
			$nestedESXiIPAddress = $_.ip
			Write-Log "Adding ESXi host $nestedESXiIPAddress to Cluster"

			# Verify VMHost is not already a member of the Cluster
			if((Get-VMHost -Server $nVCSA | Where-Object -Property Name -eq -Value $nestedESXiIPAddress) -eq $null) {
				# Move VMHost into the vSphere Cluster
				Add-VMHost -Server $nVCSA -Location $nCluster -User "root" -Password $podConfig.general.password -Name $nestedESXiIPAddress -Force | Out-File -Append -LiteralPath $verboseLogFile
			} else {
				Write-Log "ESXi host exists, skipping" -Warning
			}

			# Assign License to VMHost
			Assign-SoftwareLicense -Server $nVCSA -Asset $nestedESXiIPaddress -Vendor VMware -Product vSphere | Out-Null
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
			if(($distributedSwitch | Get-VMHost | Where-Object {$_.Name -eq $nHost.Name}) -eq $null) {
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
			if((Get-VMHostNetworkAdapter -DistributedSwitch (Get-VDSwitch -Name $podConfig.vcsa.distributedSwitch ) | Where-Object { $_.VMHost.Name -eq $nHost.Name -and $_.DeviceName -eq "vmnic1"}) -eq $NULL) {
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
			if((Get-VMHostNetworkAdapter -DistributedSwitch (Get-VDSwitch -Name $podConfig.vcsa.distributedSwitch ) | Where-Object { $_.VMHost.Name -eq $nHost.Name -and $_.DeviceName -eq "vmnic0"}) -eq $NULL) {
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
			if((Get-VMHost $nHost | Get-VMHostNetworkAdapter -VMKernel | Select-Object vmotionenabled) -ne $false) {
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
			Assign-SoftwareLicense -Server $nVCSA -Vendor VMware -Product vSAN -Asset $podConfig.vcsa.cluster | Out-Null
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
	$pESXi = $pCluster | Get-VMHost -Server $pVCSA | Where-Object { $_.ConnectionState -eq "Connected" } | Get-Random
	$NSXhostname = "$($podConfig.nsx.name).$($podConfig.target.network.domain)"

	if((Get-VM -Server $pVCSA | Where-Object -Property Name -eq -Value $podConfig.nsx.name) -eq $null) {
		Write-Log "Deploying NSX Manager"
		#splat all the parameters
		$nsxManagerBuildParams = @{
			NsxManagerOVF           = $NSXAppliance
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

	# Install and Assign NSX License
	Install-SoftwareLicense -Server $nVCSA -Vendor VMware -Product NSXv | Out-Null
	Assign-SoftwareLicense  -Server $nVCSA -Vendor VMware -Product NSXv | Out-Null

	# Prepare Controllers
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
	$clusterStatus = ($nCluster | Get-NsxClusterStatus | Select-Object -first 1).installed
	if($clusterStatus -eq "false") {
		Write-Log "Initiating installation of NSX agents"
		$nCluster | Install-NsxCluster -VxlanPrepTimeout 300 | Out-File -Append -LiteralPath $verboseLogFile
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

	$vxlanStatus =  (Get-NsxClusterStatus $nCluster | Where-Object {$_.featureId -eq "com.vmware.vshield.vsm.vxlan" }).status | Out-File -Append -LiteralPath $verboseLogFile
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
Write-Log "--------------------------------------------------------"
Write-Log "Pod Deployment Complete!"
Write-Log "StartTime: $StartTime"
Write-Log "  EndTime: $EndTime"
Write-Log " Duration: $duration minutes"
Write-Host -ForegroundColor Magenta "`nFatPacket Labs - Where Rebuilds Happen`n"