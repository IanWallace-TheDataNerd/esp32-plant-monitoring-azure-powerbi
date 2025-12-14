# Google Sheets (Backup Logging)

This folder contains the optional Google Sheets logging setup for this project.

When enabled, the ESP32 can send an HTTP POST request with JSON sensor data
(Temperature, Humidity, Soil) to a Google Apps Script Web App. The script
parses the JSON payload and appends a new row in a Google Sheet with a timestamp
and the sensor values.

This provides a simple backup data-logging path if Azure/Power BI is unavailable
or if a lightweight dataset export is needed.

## Google Sheet (Data Log)
Project data log sheet:
https://docs.google.com/spreadsheets/d/1B0nXNBtrBfgFmWmOuLMvDmokdOU13IKGi-LUfp3EBGE/edit?gid=0#gid=0

## Apps Script: `doPost(e)`

Create a new Google Apps Script project, paste the code below, then deploy it as a
**Web app** so it can accept POST requests.

```javascript
function doPost(e) {
  try {
    // Check if POST data exists
    if (!e || !e.postData || !e.postData.contents) {
      return ContentService.createTextOutput("⚠️ No POST data received");
    }

    // Parse the JSON data sent from ESP32
    var data = JSON.parse(e.postData.contents);

    // Open the active Google Sheet
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();

    // Append new row with timestamp + sensor values
    sheet.appendRow([
      new Date(),                // Timestamp
      data.Temperature,          // Temperature °C
      data.Humidity,             // Humidity %
      data.Soil                  // Soil moisture %
    ]);

    // Send confirmation back to ESP32
    return ContentService.createTextOutput("✅ Data logged successfully");
  } catch (err) {
    // Send any errors back to Serial Monitor for debugging
    return ContentService.createTextOutput("❌ Error: " + err.message);
  }
}

