# Analyzing HTTP Log Files Using Splunk SIEM

## Introduction

HTTP (Hypertext Transfer Protocol) logs record requests made to websites and web applications. These logs can include source IP addresses, request methods, URLs, response codes, user agents, and transferred data.

Security analysts can use HTTP logs to identify scanning, repeated errors, suspicious requests, unauthorized access attempts, and other potential web threats. Splunk SIEM provides a centralized platform for searching, analyzing, and monitoring these events.

## Project Overview

In this project, you will upload a sample HTTP log file into Splunk SIEM and perform basic security analysis. You will learn how to review request methods, frequently accessed URLs, response codes, active source IP addresses, traffic spikes, and suspicious web activity.

## Prerequisites

Before analyzing HTTP logs in Splunk, ensure the following:

- Splunk Enterprise is installed and configured.
- You can access the Splunk Web interface.
- A sample HTTP log file is available.
- You have permission to upload data into Splunk.
- The log contains details such as timestamps, source IP addresses, HTTP methods, URLs, response codes, and user agents.

## Steps to Upload Sample HTTP Log Files to Splunk SIEM

### 1. Prepare the Sample HTTP Log File

- Obtain a sample [HTTP log file](https://www.secrepo.com/maccdc2012/http.log.gz) in a supported format such as `.log`, `.txt`, or `.csv`.
- Extract the downloaded `.gz` file if required.
- Confirm that the file contains valid HTTP events.
- Check whether the logs include timestamps, source IP addresses, request methods, URLs, response codes, and user agents.
- Save the file in a location accessible from the system running Splunk.

### 2. Upload the Log File to Splunk

- Log in to the Splunk Web interface.
- Navigate to **Settings** > **Add Data**.
- Select **Upload** as the data input method.

### 3. Choose the HTTP Log File

- Click **Select File**.
- Locate and select the prepared HTTP log file.
- Click **Next** to continue.

### 4. Set the Source Type

- Open the **Set Source Type** section.
- Review how Splunk displays and separates the events.
- Select an existing HTTP source type or create a custom source type.
- For this project, use `http_sample`.

### 5. Review the Input Settings

- Set the index to `http_logs`.
- Enter a suitable host name for the web server that generated the logs.
- Keep the detected file name as the source.
- Confirm that the source type is `http_sample`.
- Ensure that all settings match the uploaded HTTP log file.

### 6. Submit the Log File

- Click **Review** after completing the configuration.
- Verify the index, host, source, and source type.
- Click **Submit** to upload the file into Splunk.
- Select **Start Searching** after the upload is complete.

### 7. Verify the Upload

- Open the Splunk Search application.
- Set the time range to **All time** because the sample file may contain older events.
- Run the following SPL query:

```spl
index=http_logs sourcetype=http_sample
```

If you used a different index or source type, replace `http_logs` and `http_sample` with the correct values.

To check the total number of uploaded events, run:

```spl
index=http_logs sourcetype=http_sample
| stats count AS total_http_events
```

## Steps to Analyze HTTP Log Files in Splunk SIEM

### 1. Search for HTTP Events

- Open the Splunk Search application.
- Enter the following query to display all uploaded HTTP events:

```spl
index=http_logs sourcetype=http_sample
```

### 2. Extract Relevant HTTP Information

- Identify important HTTP fields such as source IP, request method, URI, response status, bytes, and user agent.
- Check the **Interesting Fields** section in Splunk before manually extracting fields. Your source type may already provide them.
- If the events use a common web-access-log format, try the following example extraction:

```spl
index=http_logs sourcetype=http_sample
| rex field=_raw "^(?<src_ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+\"(?<method>[A-Z]+)\s+(?<uri>\S+)\s+HTTP/[^\"]+\"\s+(?<status>\d{3})\s+(?<bytes>\d+|-)"
| table _time src_ip method uri status bytes
```

Common field names include:

- `src_ip`, `clientip`, or `src`
- `method` or `http_method`
- `uri`, `url`, or `request`
- `status` or `status_code`
- `user_agent` or `http_user_agent`

Web-server log formats are different. Adjust the expression or field names if they do not match your data.

### 3. Analyze Web Traffic Patterns

- Review the distribution of HTTP request methods:

```spl
index=http_logs sourcetype=http_sample
| stats count AS request_count BY method
| sort - request_count
```

- Identify the most frequently accessed URLs or endpoints:

```spl
index=http_logs sourcetype=http_sample
| top limit=10 uri
```

- Review HTTP response codes:

```spl
index=http_logs sourcetype=http_sample
| stats count AS response_count BY status
| sort status
```

- Identify the source IP addresses generating the most requests:

```spl
index=http_logs sourcetype=http_sample
| top limit=10 src_ip
```

### 4. Detect Anomalies

- Look for sudden increases or unusual changes in HTTP traffic:

```spl
index=http_logs sourcetype=http_sample
| timechart span=5m count AS http_requests
```

- Find client or server errors with HTTP status codes of 400 or higher:

```spl
index=http_logs sourcetype=http_sample
| where tonumber(status) >= 400
| stats count AS error_count BY src_ip status uri
| sort - error_count
```

- Identify source IP addresses generating repeated `404 Not Found` responses, which may indicate web scanning:

```spl
index=http_logs sourcetype=http_sample status=404
| stats count AS not_found_count dc(uri) AS unique_uris BY src_ip
| where not_found_count >= 20
| sort - not_found_count
```

- Investigate a suspicious source IP address:

```spl
index=http_logs sourcetype=http_sample src_ip="192.0.2.10"
| table _time src_ip method uri status user_agent
| sort _time
```

Replace `192.0.2.10` with the IP address under investigation. The thresholds are examples and should be adjusted to match normal activity.

### 5. Monitor User Behaviour

- If the logs contain application login fields, identify users with repeated failed login attempts:

```spl
index=http_logs sourcetype=http_sample action="login" login_status="failed"
| stats count AS failed_attempts BY user src_ip
| where failed_attempts >= 5
| sort - failed_attempts
```

- If session IDs and usernames are available, estimate user session durations:

```spl
index=http_logs sourcetype=http_sample session_id=* user=*
| stats earliest(_time) AS session_start latest(_time) AS session_end BY user session_id
| eval session_duration_seconds=session_end-session_start
| table user session_id session_start session_end session_duration_seconds
```

These searches work only when the required application fields are present. Correlate suspicious HTTP activity with web application, WAF, firewall, authentication, and endpoint logs before making a final decision.

## Conclusion

Analyzing HTTP logs using Splunk SIEM helps security professionals understand web traffic and identify potential threats. By monitoring request methods, frequently accessed URLs, response codes, source IP addresses, traffic spikes, and failed requests, analysts can detect abnormal behaviour and investigate possible web attacks.

The searches and detection thresholds used in this project can be customized according to the web server, log format, application, and normal traffic of the environment.

Happy analyzing!
