#!/bin/bash
# ============================================================================
# sql_injection_payloads.sh
# Laboratorio: Topologia_Fortigate_Avanzada_20250742
# Autor: Jose Gabriel Feliz Maria - Matricula 2025-0742
#
# Script de prueba usado para inyectar payloads de SQL Injection contra el
# formulario web del WEB_SERVER (10.7.42.130) y verificar que la politica
# USUARIOS_WEB_HTTPS / LAB_HTTP_VALIDACION -- con el sensor IPS
# "IPS_SQLI_CUARENTENA" (firma HTTP.URI.SQL.Injection) -- bloquea el ataque
# y pone al atacante en cuarentena (Log & Report > Security Events > IPS y
# Dashboard > Quarantine en FortiGate).
#
# NOTA: reemplaza WEB_SERVER_IP y LOGIN_PATH si tu ruta del formulario es
# distinta. Ejecutar desde la VM atacante (Kali, 10.7.42.10 en la VLAN de
# Usuarios) contra el WEB_SERVER en la VLAN20_WEB.
# ============================================================================

WEB_SERVER_IP="10.7.42.130"
LOGIN_PATH="/login.php"   # <-- ajustar a la ruta real del formulario probado

PAYLOADS=(
  "' OR '1'='1"
  "' OR '1'='1' -- "
  "' OR 1=1#"
  "admin' --"
  "' UNION SELECT NULL,NULL,NULL-- -"
  "1' AND SLEEP(5)-- -"
  "'; DROP TABLE users;--"
)

echo "== Prueba de SQL Injection contra http://${WEB_SERVER_IP}${LOGIN_PATH} =="
echo "== FortiGate debe bloquear cada intento y loggear la firma HTTP.URI.SQL.Injection =="
echo

for p in "${PAYLOADS[@]}"; do
  echo "--- Payload: ${p}"
  curl -s -o /dev/null -w "HTTP %{http_code}\n" \
    --data-urlencode "username=${p}" \
    --data-urlencode "password=x" \
    "http://${WEB_SERVER_IP}${LOGIN_PATH}"
  echo
done

echo "Verificar el resultado en el FortiGate:"
echo "  Log & Report -> Security Events -> Intrusion Prevention (accion: dropped)"
echo "  Dashboard -> Quarantine (IP del atacante baneada por IPS)"
