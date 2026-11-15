p = 'crates/tools/src/windows.rs'
s = open(p).read()
a = s.index('const REGISTRY_QUERY: &str =')
b = s.index('const REGISTRY_SET: &str =')
new = r'''const REGISTRY_QUERY: &str = "$p = 'Registry::' + $env:NB_KEY;\
     function Read-Value($item, $n) {\
       $v = $item.GetValue($n);\
       switch ($item.GetValueKind($n).ToString()) {\
         'DWord' { [BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$v), 0) }\
         'QWord' { [BitConverter]::ToUInt64([BitConverter]::GetBytes([int64]$v), 0) }\
         default { ,$v }\
       }\
     }\
     $item = Get-Item -LiteralPath $p;\
     if ($env:NB_VALUE) {\
       if ($item.GetValueNames() -notcontains $env:NB_VALUE) { throw \"the key has no value named $($env:NB_VALUE)\" }\
       [pscustomobject]@{ key=$env:NB_KEY; value=$env:NB_VALUE; type=$item.GetValueKind($env:NB_VALUE).ToString(); data=(Read-Value $item $env:NB_VALUE) } | ConvertTo-Json -Depth 4\
     } else {\
       $values = [ordered]@{};\
       foreach ($n in $item.GetValueNames()) { $values[$n] = Read-Value $item $n }\
       [pscustomobject]@{ key=$env:NB_KEY; subkeys=@($item.GetSubKeyNames()); values=$values } | ConvertTo-Json -Depth 4\
     }";

'''
s = s[:a] + new + s[b:]
open(p, 'w').write(s)
