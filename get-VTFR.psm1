# Search VirusTotal for a hash from a file
# original script by Chris Shearer
# updated by John Tincher 
# Submit a file hash to VirusTotal using a .csv file for input
# File format <filename>,<filehash>
# .\get-VTFR.ps1 .\<filename>
# 23-June-2022

param 
	(
		[parameter(Mandatory=$true, Position=0)] [string] $file
	)

# test if $file exists
	if (Test-Path $file)
		{
			Write-Host "$file exists"
		}
	else
		{
			Write-Error "$file does not exist" -ErrorAction Stop
		}

# Get your own VT API key here: https://www.virustotal.com/gui/join-us
	$VTApiKey = "<api key>"

# Set TLS 1.2
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Function submit-VTHash($VThash)
	{
		$VTbody = @{resource = $VThash; apikey = $VTApiKey}
		$VTresult = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $VTbody

		return $vtResult
	}

# Get contents of $file
	[string[]]$h = Get-Content $file

foreach ($value in $h)
	{
		# Find the , and divide the line between the file name and the hash
			$comma = $value.IndexOf(',')
			$length = $value.length
			$fileName = $value.substring(0,$comma)
			$startHash = $comma + 1
			$lenHash = $length - $startHash
			$hash = $value.substring($startHash,$lenHash)
            
        # Submit the hash
            $VTresult = submit-VTHash($hash)
            
        # Color positive results
            if ($VTresult.positives -ge 1) 
				{
					$fore = "Magenta"
					$VTpct = (($VTresult.positives) / ($VTresult.total)) * 100
					$VTpct = [math]::Round($VTpct,2)
				}
            else 
				{
                    $fore = (get-host).ui.rawui.ForegroundColor
                    $VTpct = 0
                }

        # Display results
            Write-Host "==================="
			Write-Host -f Cyan "File Name   : " -NoNewline; Write-Host $fileName
			# Write-Host -f Cyan "Hash        : " -NoNewline; Write-Host $hash
			Write-Host -f Cyan "Resource    : " -NoNewline; Write-Host $VTresult.resource
            Write-Host -f Cyan "Scan date   : " -NoNewline; Write-Host $VTresult.scan_date
            Write-Host -f Cyan "Positives   : " -NoNewline; Write-Host $VTresult.positives -f $fore
            Write-Host -f Cyan "Total Scans : " -NoNewline; Write-Host $VTresult.total
            Write-Host -f Cyan "Permalink   : " -NoNewline; Write-Host $VTresult.permalink
            Write-Host -f Cyan "Percent     : " -NoNewline; Write-Host $VTpct "%" -f $fore
                
	    # Set sleep value to respect API limits (4/min) - https://developers.virustotal.com/v3.0/reference#public-vs-premium-api
	        Start-Sleep -seconds 15
		
	}
