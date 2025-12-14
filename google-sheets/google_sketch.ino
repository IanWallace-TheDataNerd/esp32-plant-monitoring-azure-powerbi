/******** ESP32 + DHT11 + Soil → Google Sheets ********
 * DHT11 on GPIO 5, Soil AO on GPIO 34
 * Sends data to Google Sheets using Apps Script Web App URL
 *******************************************************/

#include <WiFi.h>
#include <HTTPClient.h>
#include <DHT.h>

// ======== YOUR VALUES ======== //
const char* WIFI_SSID = "";
const char* WIFI_PASS = "";

// Google Apps Script Web App URL (replace this)
const char* GOOGLE_SCRIPT_URL = " ";

// ======== SENSOR PINS ======== //
#define DHTPIN   5
#define DHTTYPE  DHT11
#define SOIL_PIN 34

// ======== SETTINGS ======== //
unsigned long SEND_INTERVAL_MS = 5000;  // Send data every 5 seconds
int SOIL_RAW_DRY = 3000;                // Adjust for your sensor
int SOIL_RAW_WET = 1200;                // Adjust for your sensor

DHT dht(DHTPIN, DHTTYPE);

// ---------------- SETUP ----------------
void setup() {
  Serial.begin(115200);
  dht.begin();
  delay(500);

  Serial.printf("Connecting to WiFi: %s\n", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.printf("\n✅ WiFi Connected! IP: %s\n", WiFi.localIP().toString().c_str());
}

// ---------------- LOOP ----------------
unsigned long lastSend = 0;

void loop() {
  unsigned long now = millis();
  if (now - lastSend >= SEND_INTERVAL_MS) {
    lastSend = now;

    // Read sensors
    float temperature = dht.readTemperature();
    float humidity = dht.readHumidity();
    int soilRaw = analogRead(SOIL_PIN);

    // Convert soil reading to percentage
    float soilPercent = map(soilRaw, SOIL_RAW_DRY, SOIL_RAW_WET, 0, 100);
    soilPercent = constrain(soilPercent, 0, 100);

    if (isnan(temperature) || isnan(humidity)) {
      Serial.println("Sensor read failed!");
      return;
    }

    // Print values to Serial
    Serial.printf("Temp: %.2f°C  Humidity: %.2f%%  Soil: %.2f%%\n",
                  temperature, humidity, soilPercent);

    // Send data to Google Sheet
    sendToGoogleSheet(temperature, humidity, soilPercent);
  }
}

// ---------------- FUNCTION TO SEND DATA ----------------
void sendToGoogleSheet(float t, float h, float soil) {
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    http.begin(GOOGLE_SCRIPT_URL);
    http.addHeader("Content-Type", "application/json");

    // Create JSON payload
    String json = "{\"Temperature\":" + String(t) +
                  ",\"Humidity\":" + String(h) +
                  ",\"Soil\":" + String(soil) + "}";

    int httpCode = http.POST(json);
    if (httpCode > 0) {
      Serial.printf("✅ Sent to Google Sheets! Code: %d\n", httpCode);
    } else {
      Serial.printf("❌ Failed to send! Error: %s\n", http.errorToString(httpCode).c_str());
    }
    http.end();
  } else {
    Serial.println("⚠️ WiFi not connected!");
  }
}
