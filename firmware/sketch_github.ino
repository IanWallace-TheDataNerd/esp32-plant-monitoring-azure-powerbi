/******** ESP32 + DHT11 + Soil → Azure IoT Central via DPS (MQTT/TLS)
 * DHT11 on GPIO 5, Soil AO on GPIO 34 (ADC1).
 *********************************************************************/

// ===== CHUNK: Libraries (WiFi, TLS, MQTT, time, sensor, crypto) =====
#include <WiFi.h>                 // # WiFi functions for ESP32
#include <WiFiClientSecure.h>     // # Secure (TLS) TCP client
#include <PubSubClient.h>         // # MQTT client library for publish/subscribe
#include <time.h>                 // # Time functions (NTP + epoch time)
#include <DHT.h>                  // # DHT11 sensor library
#include "mbedtls/base64.h"       // # Base64 encode/decode (from mbedTLS crypto lib)
#include "mbedtls/md.h"           // # Message-digest (HMAC-SHA256) for SAS signatures

// ===== CHUNK: Filled-in values for WiFi + Azure DPS identity =====
const char* WIFI_SSID  = "  ";   // # WiFi network name (SSID)
const char* WIFI_PASS  = "   ";              // # WiFi password (empty = portal/open network)

const char* DPS_ID_SCOPE          = "  ";         // # DPS ID scope from Azure portal
const char* DPS_REGISTRATION_ID   = "  ";         // # Device registration ID (deviceId in DPS)
const char* DPS_DEVICE_KEY_BASE64 = "  ="; // # Device key in Base64 format

// ===== CHUNK: Options, pins, and soil calibration =====
unsigned long SEND_INTERVAL_MS = 5000;  // # Send telemetry every 5000 ms (5 seconds)
#define DHTPIN   5                       // # DHT11 signal pin on GPIO 5
#define DHTTYPE  DHT11                   // # DHT11 sensor type definition
#define SOIL_PIN 34                      // # Soil sensor analog output wired to GPIO34 (ADC1)

// Soil calibration (raw ADC values for dry vs. wet)
// You tuned these by testing sensor in dry and wet conditions.
int SOIL_RAW_DRY = 3000;         // # Approx raw ADC reading when soil is DRY
int SOIL_RAW_WET = 1200;         // # Approx raw ADC reading when sensor is in WATER
// ==================================== //

// ===== CHUNK: DPS / IoT Hub host constants and global objects =====
static const char* DPS_HOST = "global.azure-devices-provisioning.net";  // # DPS MQTT host name
static const int   MQTT_PORT = 8883;                                    // # Secure MQTT port (TLS)
static const char* DPS_API_VERSION = "2019-03-31";                      // # DPS API version string
static const char* IOTHUB_API_VERSION = "2021-04-12";                   // # IoT Hub API version string

WiFiClientSecure net;        // # Secure TCP client (handles TLS sockets)
PubSubClient mqtt(net);      // # MQTT client that uses the secure TCP client
DHT dht(DHTPIN, DHTTYPE);    // # DHT sensor object bound to pin and sensor type

String assignedHub;          // # IoT Hub host name assigned by DPS
String deviceId;             // # Device ID confirmed by DPS for IoT Hub
String iothubPublishTopic;   // # MQTT topic used to send telemetry to IoT Hub
time_t sasExpiry = 0;        // # Time when current SAS token expires (epoch seconds)
const int SAS_TTL_SECS = 60 * 60; // 1 hour                         // # SAS token lifetime in seconds

// DPS response capture globals
volatile bool dpsMsgArrived = false; // # Flag indicating a DPS MQTT message has arrived
String dpsLastTopic, dpsLastPayload; // # Store last DPS topic and payload for parsing

// ===== CHUNK: URL encoding helper (used for SAS token pieces) =====
String urlEncode(const String &value) {                 // # Encode a string for safe use in URLs
  String encoded = "";                                  // # Output string buffer
  const char *hex = "0123456789ABCDEF";                 // # Hex characters for % encoding
  for (size_t i = 0; i < value.length(); i++) {         // # Loop through each character
    char c = value.charAt(i);                           // # Current character
    // # If character is unreserved (safe), keep it
    if (('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
        c == '-' || c == '_' || c == '.' || c == '~') {
      encoded += c;                                     // # Append safe character
    } else { 
      // # Otherwise encode as %HH
      encoded += '%';                                   // # Start percent-escape
      encoded += hex[(c >> 4) & 0xF];                   // # High nibble of byte as hex
      encoded += hex[c & 0xF];                          // # Low nibble of byte as hex
    }
  }
  return encoded;                                       // # Return URL-encoded string
}

// ===== CHUNK: Base64 helpers for keys and signatures =====
bool base64Decode(const String &in, uint8_t *out, size_t outLen, size_t *written) {
  // # Decode Base64 string 'in' into raw bytes 'out'
  int ret = mbedtls_base64_decode(out, outLen, written,
                                  (const unsigned char*)in.c_str(), in.length()); // # Call mbedTLS decode
  return ret == 0;                                     // # Return true if decode succeeded
}

String base64Encode(const uint8_t *in, size_t inLen) {
  // # Encode raw bytes into a Base64 string
  size_t need = 0; 
  mbedtls_base64_encode(nullptr, 0, &need, in, inLen);   // # Ask how many bytes are needed
  unsigned char* out = (unsigned char*)malloc(need + 1); // # Allocate output buffer (+1 for null)
  if (!out) return String();                             // # If allocation fails, return empty string
  size_t written = 0;                                    // # Will hold actual length written
  String res;                                            // # Result string
  if (mbedtls_base64_encode(out, need, &written, in, inLen) == 0) {
    out[written] = 0;                    // # Null-terminate C string
    res = String((char*)out);            // # Convert to Arduino String
  }
  free(out);                             // # Free heap memory
  return res;                            // # Return Base64-encoded string
}

// ===== CHUNK: Build SAS token using HMAC-SHA256 =====
// High-level: take resource URI + expiry time, sign with device key (HMAC-SHA256),
// then Base64 + URL encode to build the final SharedAccessSignature string.
String buildSasToken(const String &resourceUri, const String &keyBase64, time_t expiry) {
  uint8_t key[64]; size_t keyLen = 0;                       // # Buffer for decoded device key and length
  // # Decode the Base64 device key into raw bytes
  if (!base64Decode(keyBase64, key, sizeof(key), &keyLen)) {
    Serial.println("ERROR: Base64 decode of device key failed"); return "";
  }
  String sr = resourceUri; sr.toLowerCase();                // # Azure expects lowercase resource URI
  String toSign = urlEncode(sr) + "\n" + String((unsigned long)expiry); // # String "sr\nse" to sign

  // ===== Inner HMAC-SHA256 block (actual signing) =====
  unsigned char hmac[32];                               // # Buffer for 32-byte HMAC-SHA256 result
  mbedtls_md_context_t ctx;                             // # HMAC/SHA256 context structure
  const mbedtls_md_info_t *mdInfo =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);     // # Get info about SHA256 algorithm
  mbedtls_md_init(&ctx);                                // # Initialize context
  mbedtls_md_setup(&ctx, mdInfo, 1);                    // # Setup context for HMAC with SHA256
  mbedtls_md_hmac_starts(&ctx, key, keyLen);            // # Begin HMAC with device key
  mbedtls_md_hmac_update(&ctx,
                         (const unsigned char*)toSign.c_str(),
                         toSign.length());              // # Feed "sr\nse" data into HMAC
  mbedtls_md_hmac_finish(&ctx, hmac);                   // # Finish HMAC; output goes into hmac[]
  mbedtls_md_free(&ctx);                                // # Free context resources

  // # Base64 encode signature and then URL encode it for the token
  String sig = urlEncode(base64Encode(hmac, sizeof(hmac)));
  // # Build final SAS token string for MQTT password or connection
  return "SharedAccessSignature sr=" + urlEncode(sr) +
         "&sig=" + sig +
         "&se=" + String((unsigned long)expiry);
}

// ===== CHUNK: Connect ESP32 to WiFi =====
void connectWiFi() {
  Serial.printf("WiFi: connecting to %s ...\n", WIFI_SSID); // # Print SSID we're connecting to
  WiFi.mode(WIFI_STA);                  // # Set WiFi to station mode (client)
  WiFi.begin(WIFI_SSID, WIFI_PASS);     // # Start connection attempt to AP
  uint8_t tries = 0;                    // # Counter for connection attempts
  while (WiFi.status() != WL_CONNECTED) { // # Loop until connected
    delay(500);                         // # Wait 0.5 seconds
    Serial.print(".");                  // # Print progress dot
    if (++tries > 60) {                 // # If more than ~30s (60 * 0.5s) passed
      Serial.println("\nWiFi timeout; rebooting"); // # Log timeout
      ESP.restart();                    // # Reboot the ESP32
    }
  }
  Serial.printf("\nWiFi OK. IP: %s\n",
                WiFi.localIP().toString().c_str()); // # Print local IP address
}

// ===== CHUNK: Sync NTP time so SAS timestamps are valid =====
void syncTime() {
  configTime(0,0,"pool.ntp.org","time.nist.gov"); // # Configure NTP servers for time
  Serial.print("Syncing time");                   // # Log that we're syncing
  time_t now=0;                                   // # Holds current epoch time
  for (int i=0; i<60 && now<1700000000; i++){    // # Try up to 60 times or until time is valid
    delay(500);                                   // # Wait 0.5 seconds
    Serial.print(".");                            // # Progress dot
    now = time(nullptr);                          // # Read current epoch time
  }
  Serial.printf("\nEpoch: %lu\n", (unsigned long)now); // # Print final epoch time
}

// ===== CHUNK: Tiny JSON helpers for DPS MQTT topics/payloads =====
int topicStatusCode(const String& topic) {
  // # Extract status code (like 200, 202) from DPS topic string
  int p = topic.indexOf("/res/");       // # Find "/res/"
  if (p < 0) return -1;                 // # If not found, return -1
  if (p+9 > (int)topic.length()) return -1; // # Bounds check
  return topic.substring(p+5, p+8).toInt(); // # Take 3 chars after "/res/" and convert to int
}

String jsonGet(const String& s, const char* key) {
  // # Grab simple "key":"value" string from JSON-ish payload
  String patt = String("\"") + key + "\":\""; // # Pattern like "key":"
  int p = s.indexOf(patt);                    // # Find start
  if (p < 0) return "";                       // # Not found
  p += patt.length();                         // # Move past the pattern
  int q = s.indexOf("\"", p);                 // # Find closing quote
  if (q < 0) return "";                       // # No closing quote
  return s.substring(p, q);                   // # Return value between quotes
}

String jsonGetNested(const String& s, const char* parentKey, const char* childKey) {
  // # Get childKey from inside a { } under parentKey
  String parent = String("\"") + parentKey + "\":{"; // # Pattern for parent object
  int p = s.indexOf(parent);                         // # Find parent
  if (p < 0) return "";                              // # Parent not found
  p += parent.length();                              // # Move to content after ":{"
  int end = s.indexOf("}", p);                       // # Find end of object
  if (end < 0) end = s.length();                     // # Fallback to end of string
  String sub = s.substring(p, end+1);                // # Take substring of nested object
  return jsonGet(sub, childKey);                     // # Use jsonGet to pull child value
}

// ===== CHUNK: MQTT callback for DPS responses =====
void mqttCallback(char* topic, byte* payload, unsigned int length) {
  // # Called when a subscribed MQTT message is received from DPS
  char buf[2001];                                  // # Local buffer for payload (+1 for null)
  unsigned int n = length > 2000 ? 2000 : length;  // # Limit copy to 2000 bytes
  memcpy(buf, payload, n);                         // # Copy payload bytes
  buf[n] = 0;                                      // # Null-terminate buffer
  dpsLastTopic   = String(topic);                  // # Save topic as String
  dpsLastPayload = String(buf);                    // # Save payload as String
  dpsMsgArrived  = true;                           // # Flag that a message arrived
}

// ===== CHUNK: Use DPS to get assigned IoT Hub + confirmed deviceId =====
bool dpsRegisterAndGetHub() {
  net.setInsecure();  // for quick start (skip CA validation)  // # Accept any TLS cert (not secure for prod)
  mqtt.setServer(DPS_HOST, MQTT_PORT);           // # Configure MQTT to connect to DPS host
  mqtt.setCallback(mqttCallback);                // # Set callback to handle incoming DPS messages
  mqtt.setBufferSize(2048);                      // # Increase buffer for DPS JSON payloads

  // ===== Build SAS token for DPS connection =====
  time_t now = time(nullptr);                    // # Current time
  sasExpiry = now + SAS_TTL_SECS;                // # SAS expiry time for DPS
  String dpsResource = String(DPS_ID_SCOPE) +
                       "/registrations/" +
                       DPS_REGISTRATION_ID;      // # Resource URI for DPS SAS signing
  String dpsSas = buildSasToken(dpsResource, DPS_DEVICE_KEY_BASE64, sasExpiry); // # Build DPS SAS token
  if (dpsSas == "") return false;                // # If failed, abort

  String dpsUsername = String(DPS_ID_SCOPE) +
                       "/registrations/" +
                       DPS_REGISTRATION_ID +
                       "/api-version=" +
                       DPS_API_VERSION;          // # DPS MQTT username string

  Serial.println("Connecting to DPS MQTT...");   // # Log DPS connect attempt
  if (!mqtt.connect(DPS_REGISTRATION_ID,        // # Client ID for MQTT
                    dpsUsername.c_str(),        // # Username
                    dpsSas.c_str())) {          // # Password (SAS token)
    Serial.println("ERROR: DPS MQTT connect failed"); 
    return false;                               // # DPS connect failed
  }
  mqtt.subscribe("$dps/registrations/res/#");   // # Subscribe to DPS responses topic wildcard

  // ===== Send initial registration request =====
  static unsigned rid = 1;                      // # Request ID counter
  String registerTopic =
      String("$dps/registrations/PUT/iotdps-register/?$rid=") + rid++; // # Registration topic with $rid
  String regPayload =
      String("{\"registrationId\":\"") + DPS_REGISTRATION_ID + "\"}";  // # JSON body with registrationId
  mqtt.publish(registerTopic.c_str(), regPayload.c_str());             // # Publish registration request

  unsigned long t0 = millis();                  // # Start time for waiting
  String operationId;                           // # Will hold operationId from DPS
  while (millis() - t0 < 20000) {               // # Wait up to 20 seconds for first response
    mqtt.loop();                                // # Handle incoming MQTT packets
    if (dpsMsgArrived) {                        // # Check if message arrived
      dpsMsgArrived = false;                    // # Reset flag
      int code = topicStatusCode(dpsLastTopic); // # Parse HTTP-like status code from topic
      if (code == 202) {                        // # 202: accepted, but still assigning
        operationId = jsonGet(dpsLastPayload, "operationId"); // # Extract operationId
        break;                                  // # Break to start polling loop
      } else if (code == 200) {                 // # 200: assigned immediately
        assignedHub = jsonGetNested(dpsLastPayload,
                                    "registrationState",
                                    "assignedHub"); // # Extract IoT Hub host
        deviceId    = jsonGetNested(dpsLastPayload,
                                    "registrationState",
                                    "deviceId");    // # Extract confirmed deviceId
        if (assignedHub.length() && deviceId.length()) {
          mqtt.disconnect();                    // # Disconnect from DPS
          return true;                          // # Success: we have hub and deviceId
        }
      } else {
        Serial.printf("DPS unexpected status: %d\n", code); // # Log unexpected DPS code
      }
    }
  }
  if (operationId == "") {                      // # If no operationId came back
    Serial.println("ERROR: DPS no operationId"); 
    return false;                               // # Fail
  }

  // ===== Poll DPS until status is 'assigned' =====
  for (int tries = 0; tries < 20; tries++) {    // # Try up to 20 polls
    String getTopic =
      String("$dps/registrations/GET/iotdps-get-operationstatus/?$rid=") +
      rid++ +
      "&operationId=" + operationId;            // # Build polling topic
    mqtt.publish(getTopic.c_str(), "");         // # Publish empty payload to query status

    unsigned long t1 = millis();                // # Poll start time
    while (millis() - t1 < 5000) {              // # Wait up to 5 seconds for reply
      mqtt.loop();                              // # Process MQTT
      if (dpsMsgArrived) {                      // # If reply arrived
        dpsMsgArrived = false;                  // # Reset flag
        int code = topicStatusCode(dpsLastTopic); // # Get status code again
        if (code == 200) {                      // # 200: valid response
          String status = jsonGet(dpsLastPayload, "status"); // # "assigning" or "assigned"
          if (status == "assigned") {           // # If assigned
            assignedHub = jsonGetNested(dpsLastPayload,
                                        "registrationState",
                                        "assignedHub"); // # Get assigned hub
            deviceId    = jsonGetNested(dpsLastPayload,
                                        "registrationState",
                                        "deviceId");    // # Get confirmed deviceId
            mqtt.disconnect();                  // # Disconnect from DPS
            return assignedHub.length() && deviceId.length(); // # True if both non-empty
          }
        }
        break;                                  // # Break inner wait loop; go to next poll
      }
    }
    delay(1500);                                // # Wait before next polling try
  }
  Serial.println("ERROR: DPS did not assign hub"); // # DPS never assigned a hub
  return false;                                  // # Fail after retries
}

// ===== CHUNK: IoT Hub helpers (username, SAS, MQTT connect) =====
String buildIoTHubUsername(const String& hub, const String& devId) {
  // # Build MQTT username: {hub}/{deviceId}/?api-version=...
  return hub + "/" + devId + "/?api-version=" + IOTHUB_API_VERSION;
}

String buildIoTHubSas(const String& hub, const String& devId) {
  // # Build SAS token for IoT Hub connection using same device key
  time_t now = time(nullptr);                   // # Current time
  sasExpiry = now + SAS_TTL_SECS;               // # New expiry time
  String res = hub + "/devices/" + devId;       // # Resource URI for IoT Hub SAS
  return buildSasToken(res, DPS_DEVICE_KEY_BASE64, sasExpiry); // # Call buildSasToken
}

bool ensureIoTHubMqtt() {
  // # Ensure we are connected to IoT Hub via MQTT (reconnect if needed)
  if (mqtt.connected()) return true;            // # Already connected → nothing to do
  net.setInsecure();                            // # Skip TLS cert validation (quick start)
  mqtt.setServer(assignedHub.c_str(), MQTT_PORT); // # Set MQTT server to assigned IoT Hub host
  mqtt.setCallback(nullptr);                    // # No callback needed for simple telemetry
  mqtt.setBufferSize(512);                      // # Use smaller MQTT buffer for telemetry

  String user = buildIoTHubUsername(assignedHub, deviceId); // # Build MQTT username for hub
  String pass = buildIoTHubSas(assignedHub, deviceId);      // # Build SAS token as MQTT password
  Serial.printf("Connecting to IoT Hub %s ...\n", assignedHub.c_str()); // # Log attempt
  bool ok = mqtt.connect(deviceId.c_str(),      // # MQTT client ID
                         user.c_str(),          // # Username
                         pass.c_str());         // # Password (SAS token)
  Serial.println(ok ? "IoT Hub MQTT connected." // # Log success
                     : "IoT Hub MQTT connect failed."); // # Log failure
  return ok;                                     // # Return connection status
}

// ===== CHUNK: Soil reading helpers (ADC → percent) =====
int readSoilRaw() {
  // # Read raw analog value from soil sensor on GPIO34 (ADC1)
  return analogRead(SOIL_PIN);   // # Returns integer 0..4095 on most ESP32 cores
}

float soilRawToPercent(int raw) {
  // # Convert raw soil ADC reading into a 0–100% moisture value
  raw = constrain(raw, SOIL_RAW_WET, SOIL_RAW_DRY); // # Clamp raw value inside calibration range
  // # Map dry (SOIL_RAW_DRY) → 0%, wet (SOIL_RAW_WET) → 100%
  return 100.0f * (SOIL_RAW_DRY - raw) / (SOIL_RAW_DRY - SOIL_RAW_WET);
}

// ===== CHUNK: Publish telemetry JSON to IoT Hub =====
void publishTelemetry(float tC, float h, float soilPct, int soilRaw) {
  // # Publish JSON telemetry with temperature, humidity, soil percent, and timestamp
  if (iothubPublishTopic.length() == 0) {       // # Build topic only once
    iothubPublishTopic  = "devices/";           // # Start with "devices/"
    iothubPublishTopic += deviceId;             // # Add current deviceId
    iothubPublishTopic += "/messages/events/";  // # Finish with events path
  }
  char payload[220];                            // # Buffer for JSON string
  unsigned long ts = (unsigned long)time(nullptr); // # Current epoch timestamp in seconds

  // # Format JSON payload with numeric fields
  snprintf(payload, sizeof(payload),
           "{\"Temperature\":%.2f,\"Humidity\":%.2f,\"Soil\":%.2f,\"ts\":%lu}",
           tC, h, soilPct, ts);                 // # Create JSON string into payload buffer

  Serial.print("Publish: ");                    // # Log prefix
  Serial.println(payload);                      // # Print JSON payload to Serial Monitor

  if (!mqtt.publish(iothubPublishTopic.c_str(), payload)) {
    Serial.println("Publish failed.");          // # If publish returns false, log failure
  }
}

// ===== CHUNK: Global timer for telemetry interval =====
unsigned long lastSend = 0;  // # Stores last millis() time telemetry was sent

// ===== CHUNK: setup() – one-time initialization =====
void setup() {
  Serial.begin(115200);            // # Start serial communication at 115200 baud
  delay(200);                      // # Small delay for Serial to settle
  Serial.println("\nESP32 + DHT11 + Soil → Azure IoT Central via DPS (MQTT)"); // # Banner message
  dht.begin();                     // # Initialize DHT11 sensor
  connectWiFi();                   // # Connect to WiFi network
  syncTime();                      // # Sync NTP time (needed for SAS tokens)

  deviceId = String(DPS_REGISTRATION_ID); // # Start with registration ID as deviceId
  if (!dpsRegisterAndGetHub()) {         // # Use DPS to get assigned IoT Hub and deviceId
    Serial.println("Provisioning failed. Rebooting in 10s..."); // # Log failure
    delay(10000);               // # Wait 10 seconds for you to see message
    ESP.restart();              // # Reboot board to try again
  }
  Serial.printf("Assigned hub: %s | deviceId: %s\n",
                assignedHub.c_str(),
                deviceId.c_str());       // # Log the assigned IoT Hub and deviceId
}

// ===== CHUNK: loop() – main runtime logic =====
void loop() {
  if (!ensureIoTHubMqtt()) {  // # Make sure MQTT connection to IoT Hub is active
    delay(2000);              // # Wait 2 seconds if connection failed
    return;                   // # Skip rest of loop until reconnected
  }
  mqtt.loop();                // # Service MQTT client (keep connection alive)

  unsigned long nowMs = millis(); // # Current time in milliseconds since boot
  if (nowMs - lastSend >= SEND_INTERVAL_MS) { // # Check if it's time to send telemetry
    lastSend = nowMs;            // # Update lastSend timestamp

    float h = dht.readHumidity();       // # Read relative humidity from DHT11
    float t = dht.readTemperature();    // # Read temperature in Celsius from DHT11
    int   soilRaw = readSoilRaw();      // # Read raw soil sensor ADC value
    float soilPct = soilRawToPercent(soilRaw); // # Convert raw soil value to moisture percentage

    if (isnan(h) || isnan(t)) {         // # If DHT sensor returned invalid values
      Serial.println("DHT read failed; skipping"); // # Log and skip this cycle
    } else {
      publishTelemetry(t, h, soilPct, soilRaw);    // # Publish telemetry if readings are valid
    }
  }
}
