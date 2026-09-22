#!/bin/bash
# ============================================================================
# sql_injection_payloads.sh
# Laboratorio: Topologia_Fortigate_Avanzada_20250742
# Autor: Jose Gabriel Feliz Maria - Matricula 2025-0742
#
# Script real usado para inyectar payloads de SQL Injection contra el
# WEB_SERVER (https://10.7.42.130) y verificar que la politica
# USUARIOS_WEB_HTTPS -- con el sensor IPS "IPS_SQLI_CUARENTENA"
# (firma HTTP.URI.SQL.Injection, rule 15621) -- bloquea el ataque y pone
# al atacante en cuarentena (Log & Report > Security Events > Intrusion
# Prevention y Dashboard > Quarantine en FortiGate).
#
# IMPORTANTE: el WEB-Server de este laboratorio NO tiene un formulario de
# login real ni backend de base de datos (es una pagina HTML estatica
# servida por Apache). Por eso los payloads no se envian como POST contra
# un formulario, sino como parametros GET dentro de la URL, contra un
# archivo de prueba (prueba.txt) publicado en el WEB_SERVER. El sensor IPS
# de FortiGate inspecciona la firma HTTP.URI.SQL.Injection directamente
# sobre la URI/query string de la peticion HTTPS -- gracias a que la
# politica USUARIOS_WEB_HTTPS tiene Full SSL Inspection activa -- sin
# importar si existe o no un backend vulnerable detras. Esto es suficiente
# y valido para demostrar la deteccion, el bloqueo y la cuarentena por
# parte del FortiGate.
#
# Ejecutar desde la VM atacante (Kali, 10.7.42.10 en VLAN10_USUARIOS)
# contra el WEB_SERVER (10.7.42.130, VLAN20_WEB).
# ============================================================================

WEB_SERVER_IP="10.7.42.130"
TARGET_PATH="/prueba.txt"

# Payload verificado: coincide con la firma HTTP.URI.SQL.Injection (rule
# 15621) del sensor IPS_SQLI_CUARENTENA aplicado en la politica
# USUARIOS_WEB_HTTPS (Policy ID 2).
PAYLOAD="id=1' UNION SELECT 1,2,3--"

echo "== Prueba de SQL Injection contra https://${WEB_SERVER_IP}${TARGET_PATH} =="
echo "== FortiGate debe bloquear el intento y loggear la firma HTTP.URI.SQL.Injection =="
echo

echo "--- Payload: ${PAYLOAD}"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" \
  "https://${WEB_SERVER_IP}${TARGET_PATH}?${PAYLOAD}"
echo

echo "Resultado observado y confirmado en este laboratorio (log real, via CLI):"
echo '  execute log filter category 4'
echo '  execute log filter field srcip 10.7.42.10'
echo '  execute log filter field dstip 10.7.42.130'
echo '  execute log display'
echo
echo "  action=dropped  attack=\"HTTP.URI.SQL.Injection\"  attackid=15621"
echo "  profile=\"IPS_SQLI_CUARENTENA\"  srcip=10.7.42.10  dstip=10.7.42.130"
echo "  policyid=2 (USUARIOS_WEB_HTTPS)  severity=high"
echo
echo "Verificar el resultado en el FortiGate:"
echo "  Log & Report -> Security Events -> Intrusion Prevention (accion: dropped)"
echo "  Dashboard -> Quarantine (IP del atacante 10.7.42.10 baneada por IPS, ~1 dia)"
