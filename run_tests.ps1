[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Limpa log antigo
if (Test-Path logs\alerts.csv) {
    Remove-Item logs\alerts.csv
    Write-Host "[INFO] Log antigo removido"
}

# Sobe o alert_system em background
Write-Host "[INFO] Iniciando monitoramento..."
$monitor = Start-Process python -ArgumentList "alert_system.py" -PassThru -NoNewWindow

# Aguarda estabilizar
Start-Sleep -Seconds 5

# Instrução para o usuário
Write-Host ""
Write-Host "========================================"
Write-Host "  Rode o attack_suite.sh no Kali agora"
Write-Host "  sudo ./attack_suite.sh"
Write-Host "========================================"
Write-Host ""
Write-Host "Pressione ENTER quando os ataques terminarem..."
Read-Host

# Para o monitoramento
Stop-Process -Id $monitor.Id -Force 2>$null
Write-Host "[INFO] Monitoramento encerrado"

# Gera os gráficos
Write-Host "[INFO] Gerando gráficos..."
python evaluate.py

Write-Host "[INFO] Tudo pronto! Gráficos em logs/"