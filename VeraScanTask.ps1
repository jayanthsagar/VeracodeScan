[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-RandomHex {
    param(
        [int] $Bits = 256
    )
    $bytes = new-object 'System.Byte[]' ($Bits/8)
    (new-object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes)
    (new-object System.Runtime.Remoting.Metadata.W3cXsd2001.SoapHexBinary @(,$bytes)).ToString()
}

<# Returns a Byte array from a Hex String #>
Function GetByteArray {

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [String] $HexString
    )

    $Bytes = [byte[]]::new($HexString.Length / 2)

    For($i=0; $i -lt $HexString.Length; $i+=2){
        $Bytes[$i/2] = [convert]::ToByte($HexString.Substring($i, 2), 16)
    } 

    return $Bytes   
}

<# Returns nonce as a byte array#>
Function GetNonce {

    $nonce = Get-RandomHex -Bits 128 
    $nonceByteArray = GetByteArray $nonce

    return $nonceByteArray
}

Function ComputeHash ($CHData, $CHKey) {
    
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $CHKey

    $Result = $hmac.ComputeHash($CHData)

    return $Result

}

<# Construct Signature #>
Function CalculateDataSignature($apiKeyBytes, $nonceBytes, $dateStamp, $dataCDS) {

    $requestVersion = "vcode_request_version_1"
    $requestVersionBytes = [Text.Encoding]::UTF8.GetBytes($requestVersion)
    [byte[]] $kNonce = ComputeHash $nonceBytes $apiKeyBytes
    [byte[]] $kDate = ComputeHash  $dateStamp $kNonce
    [byte[]] $kSignature = ComputeHash $requestVersionBytes $kDate

    $dataSignature = ComputeHash $dataCDS $kSignature 

    return $dataSignature

}

Function CalculateAuthorizationHeader($IdCA, $apiKeyCA, $urlBaseCA, $urlPathCA, $MethodCA, $urlQueryParams)	{
    
    try {

        if (-not ([string]::IsNullOrEmpty($urlQueryParams)))
		{
			$urlPathCA += '?' + ($urlQueryParams);
		}
              
        $dataCA = "id={0}&host={1}&url={2}&method={3}" -f $IdCA, $urlBaseCA, $urlPathCA, $MethodCA
        $dataCABytes = [Text.Encoding]::UTF8.GetBytes($dataCA)
		$dateStamp = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)
        [byte[]] $dateStampbytes = [Text.Encoding]::UTF8.GetBytes($dateStamp)
        [byte[]] $nonceBytesCA = GetNonce
        $nonceHex = [System.BitConverter]::ToString($nonceBytesCA) -replace '-'
        [byte[]] $apiKeyBytes = GetByteArray $apiKeyCA
        [byte[]] $dataSignatureCA = CalculateDataSignature $apiKeyBytes $nonceBytesCA $dateStampbytes $dataCABytes
        $dateSignatureHex = [System.BitConverter]::ToString($dataSignatureCA) -replace '-'
		$authorizationParam = "id={0},ts={1},nonce={2},sig={3}" -f $IdCA, $dateStamp, $nonceHex, $dateSignatureHex 

        $AuthorizationScheme = "VERACODE-HMAC-SHA-256" + " " + $authorizationParam
        
        return $AuthorizationScheme
        
   }
    catch {
	
	    $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Host $ErrorMessage
        Write-Host $FailedItem
        Break
    }
    
}
<# The script uses environment variables to hide your API ID and Key. 
 # You will need to set up two environment variables called Veracode_API_ID and Veracode_API_Key, if you use the script as is.
 # You may use your credentials as plain text. However, that is not recommended. 
#>   
$id = ${env:VERACODE_API_ID}
$key = ${env:VERACODE_SECRET} 
$AppName = 'VeriFide'
$SandboxName = 'VeriFide Scalability'

$authorizationScheme = 'VERACODE-HMAC-SHA-256'
$requestVersion = "vcode_request_version_1"
$method = 'GET'
$urlBase = "api.veracode.com"
$urlPath = "/appsec/v1/applications/"
<# $urlQueryParams Usage
 # If you only have one parameter, do not add the '?' The code will handle it. Example: $urlQueryParams = 'app_id=420049'
 # If you have more then one parameter, ingore the first '?' but add it between each parameter. 
 # Example: $urlQueryParams = 'app_id=12345?sandbox_id=12345?version=scanname'
#>
$urlQueryParams = 'page=0&size=50'

if (-not ([string]::IsNullOrEmpty($urlQueryParams)))
{
    $url = 'https://' + $urlBase + $urlPath + '?' + $urlQueryParams
}
else 
{
    $url = 'https://' + $urlBase + $urlPath 
}

<# Construct Header #>
$authorization = CalculateAuthorizationHeader $id $key $urlBase $urlPath $method $urlQueryParams
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization",$authorization)
$headers.Add("Content-Type",'application/json')

<# Make Request #>
Try{

    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -OutFile ./vera.json

    $results = Get-Content "./vera.json" | ConvertFrom-Json
    $results = $results._embedded.applications 

    foreach ($result in $results)
    {

        if($result.profile.name -eq $AppName)
        {
        Write-Host $result.profile.name
        Write-Host $result._links.sandboxes.href
        $sbxs_path=$urlPath +$result.guid+'/sandboxes/'
        $sbxs_url='https://' + $urlBase +  $sbxs_path+ '?' + $urlQueryParams
        Write-Host $sbxs_url
        $authorization = CalculateAuthorizationHeader $id $key $urlBase $sbxs_path $method $urlQueryParams
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization",$authorization)
        $headers.Add("Content-Type",'application/json')
        $sbxs_response = Invoke-RestMethod -Uri $sbxs_url -Headers $headers -Method Get -OutFile ./sbxs.json
        $sandboxes=Get-Content "./sbxs.json" | ConvertFrom-Json
        $sandboxes=$sandboxes._embedded.sandboxes

        foreach($sandbox in $sandboxes)
            {


                if($sandbox.name -eq $SandboxName)
                {
                    Write-Host $sandbox.name
                    Write-Host $sandbox._links.self.href
                    $sbx_path=$sbxs_path+$sandbox.guid+'/'
                    $sbx_url='https://' + $urlBase +  $sbx_path+ '?' + $urlQueryParams
                    Write-Host $sbx_url
                    $authorization = CalculateAuthorizationHeader $id $key $urlBase $sbx_path $method $urlQueryParams
                    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                    $headers.Add("Authorization",$authorization)
                    $headers.Add("Content-Type",'application/json')
                    $sbxs_response = Invoke-RestMethod -Uri $sbx_url -Headers $headers -Method Get -OutFile "./sbx.json"
                    $sandboxes=Get-Content "./sbx.json" | ConvertFrom-Json
                    #https://api.veracode.com/appsec/v2/applications/{application_guid}/findings?scan_type=STATIC
                    $findingPath = "/appsec/v2/applications/"+$result.guid+"/summary_report"
                    Write-Host $findingPath
                    $urlQueryParams='context='+$sandbox.guid
                    #$urlQueryParams='scan_type=STATIC'
                    $authorization1 = CalculateAuthorizationHeader $id $key $urlBase $findingPath $method $urlQueryParams
                    $headers1 = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                    $headers1.Add("Authorization",$authorization1)
                    $headers1.Add("Content-Type",'application/json')
                    $scans_url='https://' + $urlBase +  $findingPath+ '?' + $urlQueryParams
                    Write-Host $scans_url
                    $scans_response = Invoke-RestMethod -Uri $scans_url -Headers $headers1 -Method Get -OutFile "./scans.json"
                    $scans_response_data = Get-Content "./scans.json" | ConvertFrom-Json
                    Write-Host "Application:"$result.profile.name", Sandbox:"$sandbox.name", last update on:"$scans_response_data.last_update_time
                    $scandate = $scans_response_data.last_update_time.subString(0,$scans_response_data.last_update_time.Length-4)
                    $lastupdated = [DateTime]::ParseExact($scandate, 'yyyy-MM-dd HH:mm:ss', $null)
                    $DeleteDate = (Get-Date).AddDays(-1)
                    Write-Host '##vso[task.setvariable variable=AppName, isoutput=true]$AppName'
                    Write-Host '##vso[task.setvariable variable=SandboxName, isoutput=true]$SandboxName'
                    
                    if ($lastupdated -lt $DeleteDate)
                        {
                           Write-Output "$lastupdated last scan was ran befor 7 Days ($DeleteDate) - scan will be triggered"
                            Write-Output '##vso[task.setvariable variable=runScan]true'
                        }
                    else {
                           Write-Output "$lastupdated last scan is not older than 7 Days ($DeleteDate) - scan will not be triggered "
                            Write-Output '##vso[task.setvariable variable=runScan]false'
                        }


                }
        }
        }
    }


#    Write-Host $results

}
catch {
	
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Host $ErrorMessage
    Write-Host $FailedItem
    Break
}
