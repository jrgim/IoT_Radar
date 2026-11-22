#!/usr/bin/env bash
set -e

OPTIONS="/data/options.json"

export MQTT_HOST=$(jq --raw-output '.mqtt_host // "core-mosquitto"' "$OPTIONS")
export MQTT_PORT=$(jq --raw-output '.mqtt_port // "1883"' "$OPTIONS")
export MQTT_USER=$(jq --raw-output '.mqtt_user // empty' "$OPTIONS")
export MQTT_PASSWORD=$(jq --raw-output '.mqtt_password // empty' "$OPTIONS")
export Z2M_TOPIC_PREFIX=$(jq --raw-output '.z2m_topic_prefix // "zigbee2mqtt"' "$OPTIONS")
export SCAN_INTERVAL=$(jq --raw-output '.scan_interval_minutes // "60"' "$OPTIONS")
export NVD_API_KEY=$(jq --raw-output '.nvd_api_key // empty' "$OPTIONS")
export ALERT_NOTIFY_SERVICE=$(jq --raw-output '.alert_notify_service // "notify"' "$OPTIONS")
export DB_PATH="/data/iot_radar.db"
export INGRESS_PORT="8765"

exec python3 -u /app/main.py
