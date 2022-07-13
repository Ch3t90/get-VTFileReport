# get-VTFR

- Use PowerShell to get VirusTotal report for a .csv file containing FileName/FileHash pairs.
- This API is rate limited to 4 submissions per minute.  
- VirusTotal [API documentation](https://developers.virustotal.com/reference#file-report)

## To use the module

- Import the module.

```PowerShell
PS C:\temp> Import-Module .\get-VTFR.psm1
```

- If you want to install the module for long-term use
  - See [Microsoft documentation](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module?view=powershell-7).
  - Shortcut - just copy to its own folder in this location: $Env:ProgramFiles\WindowsPowerShell\Modules

```PowerShell
PS C:\temp> copy .\get-VTFR.psm1 $Env:ProgramFiles\WindowsPowerShell\Modules\get-VTFR\get-VTFR.psm1
```

- Line 25: Enter your API key 
  - Sign up for your own [VirusTotal API key](https://www.virustotal.com/gui/join-us). 
  
- Examples:  

```PowerShell
get-VTFR <filename>
```

## The following information is returned on the screen

- Resource: the sha256 of what was submitted.
- Scan date: last date the resource was scanned.
- Positives: Number of positive results.  
- Total: Number of engines that have scanned the file.
- Permalink: Link to VT to see more information.
- Percent: Percent of positive results.
