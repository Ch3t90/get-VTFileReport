# get-VTFR
- Use PowerShell to get VirusTotal report for a .csv file with FileName/FileHash pairs.  
- This API is rate limited to 4 submissions per minute.  
- API documentation: https://developers.virustotal.com/reference#file-report

## To use this script:  
- Line 25: Enter your API key(Get your own VT API key here: https://www.virustotal.com/gui/join-us).  

## To from the CLI: 
- Example:  
```
.\get-VTFileReport.ps1 .\hashes.csv
```
## The following information is returned on the screen:
- Resource: the sha256 of what was submitted
- Scan date: last date the resource was scanned
- Positives: Number of positive results - if there are 1 or more positives, the number is returned in magenta.  
- Total: Number of engines that have scanned the file
- Permalink: Link to VT to see more information
- Percent: (positives/total) x 100 - if there are 1 or more positives, the number is returned in magenta.
