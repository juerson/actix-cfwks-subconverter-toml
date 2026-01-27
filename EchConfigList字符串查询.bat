@echo off
chcp 65001 >nul
setlocal

title ECH DNS 查询工具
cls

set "DNS_URL=https://dns.google/resolve?name=cloudflare-ech.com&type=65"

echo ===============================================================================
echo                           ECH DNS 查询工具
echo ===============================================================================
echo.
echo  DNS 服务器 : Google DNS (DoH)
echo  查询域名   : cloudflare-ech.com
echo  记录类型   : HTTPS (65)
echo.
echo ------------------------------------------------------------------------------
echo 正在查询 ECH 配置，请稍候...
echo.

powershell -NoProfile -Command "try { $r=Invoke-RestMethod '%DNS_URL%'; $d=$r.Answer[0].data; Write-Host '查询成功' -ForegroundColor Green; Write-Host ''; Write-Host '原始 DNS 记录:'; Write-Host $d; Write-Host ''; Write-Host '解析结果:'; $alpn=''; $ipv4=''; $ipv6=''; $ech=''; $d -split ' ' | %% { if ($_.StartsWith('alpn=')) { $alpn=$_.Substring(5) } elseif ($_.StartsWith('ipv4hint=')) { $ipv4=$_.Substring(9) } elseif ($_.StartsWith('ipv6hint=')) { $ipv6=$_.Substring(10) } elseif ($_.StartsWith('ech=')) { $ech=$_.Substring(4) } }; if ($alpn) { Write-Host ('  ALPN  : ' + $alpn) }; if ($ipv4) { Write-Host ('  IPv4  : ' + $ipv4) }; if ($ipv6) { Write-Host ('  IPv6  : ' + $ipv6) }; if ($ech) { Write-Host ('  ECH   : ' + $ech) -ForegroundColor Cyan } } catch { Write-Host '查询失败，请检查网络连接。' -ForegroundColor Red }"

echo.
echo ------------------------------------------------------------------------------
echo 复制提示:
echo   - 直接回车 : 复制 ECH 配置到剪贴板
echo   - 输入 n   : 不复制
echo ------------------------------------------------------------------------------
echo.

set /p copy_choice=是否复制 ECH 配置到剪贴板? [Y/n]: 

if /i "%copy_choice%"=="n" (
    echo 已取消复制。
) else (
    powershell -NoProfile -Command "$r=Invoke-RestMethod '%DNS_URL%'; $ech=($r.Answer[0].data -split ' ' | ? { $_ -like 'ech=*' }).Substring(4); Set-Clipboard $ech; Write-Host 'ECH 配置已复制到剪贴板。' -ForegroundColor Green"
)

echo.
set /p "=操作完成，按任意键退出..." <nul
pause >nul
exit /b
