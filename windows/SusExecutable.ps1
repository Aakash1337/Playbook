$SearchPathsRecursive = @(
    "C:\Users"
    "C:\inetpub"
    "C:\PerfLogs"

)
$SearchPathsNonRecursive = @(
    "C:\"
    "C:\Program Files"
    "C:\Program Files (x86)"
    "C:\ProgramData"
)

$RecursiveFiles = @(
    foreach ($path in $SearchPathsRecursive) {
        Get-ChildItem -Path $path -Recurse -Include *.exe, *.dll, *.cmd, *.bat, *.ps1 -ErrorAction SilentlyContinue #|
        #Where-Object {
        #    $_.FullName -notlike 'C:\Users\acebi\*'
        #}
    }
)

$NonRecursiveFiles = @(
    foreach ($path in $SearchPathsNonRecursive) {
        Get-ChildItem -Path $path -Include *.exe, *.dll, *.cmd, *.bat, *.ps1 -ErrorAction SilentlyContinue
    }
)

$Files = $RecursiveFiles + $NonRecursiveFiles

$Files | Select-Object FullName, Name, CreationTime | Format-List