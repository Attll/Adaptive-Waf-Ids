param([ValidateSet('normal','sqli','xss','traversal','rce','cookie','brute_force','http_flood','mixed')] [string]$Scenario='normal')
$u='http://127.0.0.1:8090/backend'
$q=@{normal='/health';sqli="/search?q=' OR 1=1--";xss='/comment?text=<script>alert(1)</script>';traversal='/download?file=../../etc/passwd';rce='/run?cmd=;cat%20/etc/passwd';cookie='/account';brute_force='/login';http_flood='/health';mixed='/search?q=1'}[$Scenario]
$n=if($Scenario -in 'brute_force','http_flood'){50}else{1}; 1..$n|%{curl.exe -s -o NUL -w "%{http_code}`n" "$u$q"}
