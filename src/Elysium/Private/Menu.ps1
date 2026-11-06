# Pure keypress-to-selection logic for Elysium.ps1's interactive console menu. No console I/O here,
# so it's testable without a real terminal; Elysium.ps1 does the reading and drawing.

function Resolve-ElysiumMenuKeyPress {
    <#
    .SYNOPSIS
    Turns one console keypress into the menu's next highlighted index and whether it chose or cancelled.

    .DESCRIPTION
    Up/Down move the highlight with wraparound. Enter commits the highlighted item. A digit key
    jumps straight to and commits that 1-based item (matching the old numbered prompt), ignored if
    out of range. Escape cancels. Anything else leaves the index unchanged.
    #>
    param(
        [Parameter(Mandatory)][int]$CurrentIndex,
        [Parameter(Mandatory)][int]$ItemCount,
        [Parameter(Mandatory)][System.ConsoleKey]$Key
    )
    switch ($Key) {
        'UpArrow'   { return [pscustomobject]@{ Index = (($CurrentIndex - 1 + $ItemCount) % $ItemCount); Committed = $false; Cancelled = $false } }
        'DownArrow' { return [pscustomobject]@{ Index = (($CurrentIndex + 1) % $ItemCount); Committed = $false; Cancelled = $false } }
        'Enter'     { return [pscustomobject]@{ Index = $CurrentIndex; Committed = $true; Cancelled = $false } }
        'Escape'    { return [pscustomobject]@{ Index = $CurrentIndex; Committed = $false; Cancelled = $true } }
        default {
            if ($Key -ge [System.ConsoleKey]::D1 -and $Key -le [System.ConsoleKey]::D9) {
                $picked = [int]$Key - [int][System.ConsoleKey]::D1
                if ($picked -lt $ItemCount) {
                    return [pscustomobject]@{ Index = $picked; Committed = $true; Cancelled = $false }
                }
            }
            return [pscustomobject]@{ Index = $CurrentIndex; Committed = $false; Cancelled = $false }
        }
    }
}
