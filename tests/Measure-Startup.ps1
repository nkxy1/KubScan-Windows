param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [ValidateRange(1, 100)][int]$Iterations = 5
)
$ErrorActionPreference = 'Stop'
$executablePath = (Resolve-Path -LiteralPath $Executable).Path
# First response isolates startup from DNS, ping and port timeouts. Keep the
# first sample separate: this script does not flush the Windows filesystem cache.
foreach ($scenario in @('--version', 'scan 127.0.0.1/32 -Ports 1')) {
    for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
        $info = [Diagnostics.ProcessStartInfo]::new($executablePath, $scenario)
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $info
        try {
            $watch = [Diagnostics.Stopwatch]::StartNew()
            [void]$process.Start()
            $errors = $process.StandardError.ReadToEndAsync()
            $first = $process.StandardOutput.ReadLineAsync()
            if (!$first.Wait(30000)) { $process.Kill(); throw 'Startup timed out.' }
            $firstMs = $watch.Elapsed.TotalMilliseconds
            $output = $process.StandardOutput.ReadToEndAsync()
            if (!$process.WaitForExit(30000)) { $process.Kill(); throw 'Scan timed out.' }
            $watch.Stop()
            if ($process.ExitCode -ne 0) { throw $errors.GetAwaiter().GetResult() }
            [void]$output.GetAwaiter().GetResult()
            [pscustomobject]@{
                Executable = $executablePath
                Scenario = $scenario
                Iteration = $iteration
                FirstOutputMs = [math]::Round($firstMs, 1)
                TotalMs = [math]::Round($watch.Elapsed.TotalMilliseconds, 1)
            }
        }
        finally { $process.Dispose() }
    }
}
