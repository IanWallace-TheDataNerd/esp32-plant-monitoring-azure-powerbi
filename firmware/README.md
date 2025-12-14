# Firmware (ESP32)

This folder contains the Arduino/ESP32 firmware for the Senior Design project.

The ESP32 reads data from a DHT11 temperature/humidity sensor and a soil moisture sensor, then formats the readings as telemetry and sends them to Azure IoT Central using DPS provisioning and MQTT over TLS.

**Note:** Secrets (Wi-Fi credentials, device keys, connection strings) are not stored in this repo. Use placeholders in code and keep real values in a local config file or Arduino IDE secrets.

