# Test helper: a minimal S3-style object store on HttpListener, served from a background runspace so
# the real HttpClient/SigV4/runspace-pool code can run against it on any OS.
# - GET <bucket>/<key> serves $Root/<bucket>/<key>, 404 if missing.
# - PUT stores the body only if it matches x-amz-content-sha256, else 400 BadDigest (as S3 does).
# - Keys containing '/flaky/' answer 503 to their first GET; keys containing '/reject/' refuse PUTs.
# Requests are logged as "<METHOD> <bucket>/<key>"; Get-FakeStorageLog drains the log.

function Start-FakeStorage {
    param([Parameter(Mandatory)][string]$Root)

    $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $probe.Start(); $port = $probe.LocalEndpoint.Port; $probe.Stop()
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("http://localhost:$port/")
    $listener.Start()
    $log = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

    $serve = {
        param($listener, $root, $log)
        $gets = @{}
        while ($listener.IsListening) {
            try { $context = $listener.GetContext() } catch { break }
            $request = $context.Request
            $response = $context.Response
            $key = [uri]::UnescapeDataString($request.Url.AbsolutePath.TrimStart('/'))
            $path = Join-Path $root $key
            $log.Enqueue("$($request.HttpMethod) $key")
            try {
                if ($request.HttpMethod -eq 'GET') {
                    $gets[$key] = 1 + [int]$gets[$key]
                    if ($key -like '*/flaky/*' -and $gets[$key] -eq 1) {
                        $response.StatusCode = 503
                    } elseif (Test-Path -LiteralPath $path -PathType Leaf) {
                        $bytes = [System.IO.File]::ReadAllBytes($path)
                        $response.ContentLength64 = $bytes.Length
                        $response.OutputStream.Write($bytes, 0, $bytes.Length)
                    } else {
                        $response.StatusCode = 404
                    }
                } elseif ($request.HttpMethod -eq 'PUT') {
                    $buffer = [System.IO.MemoryStream]::new()
                    $request.InputStream.CopyTo($buffer)
                    $body = $buffer.ToArray()
                    $sha = [System.Security.Cryptography.SHA256]::Create()
                    $actual = [BitConverter]::ToString($sha.ComputeHash($body)).Replace('-', '').ToLowerInvariant()
                    if ($key -like '*/reject/*' -or $request.Headers['x-amz-content-sha256'] -ne $actual) {
                        $response.StatusCode = 400
                        $message = [System.Text.Encoding]::UTF8.GetBytes('<Error><Code>BadDigest</Code></Error>')
                        $response.OutputStream.Write($message, 0, $message.Length)
                    } else {
                        [void][System.IO.Directory]::CreateDirectory((Split-Path -Path $path -Parent))
                        [System.IO.File]::WriteAllBytes($path, $body)
                    }
                }
            } finally {
                $response.Close()
            }
        }
    }
    $shell = [powershell]::Create()
    [void]$shell.AddScript($serve.ToString()).AddArgument($listener).AddArgument($Root).AddArgument($log)
    [pscustomobject]@{ Url = "http://localhost:$port"; Listener = $listener; Shell = $shell; Handle = $shell.BeginInvoke(); Log = $log }
}

function Stop-FakeStorage {
    param([Parameter(Mandatory)]$Server)
    $Server.Listener.Stop()
    $Server.Listener.Close()
    $Server.Shell.Dispose()
}

function Get-FakeStorageLog {
    param([Parameter(Mandatory)]$Server)
    $entry = $null
    while ($Server.Log.TryDequeue([ref]$entry)) { $entry }
}
