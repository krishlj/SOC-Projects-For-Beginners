# Analyzing FTP Log Files Using Splunk SIEM

## Introduction

FTP (File Transfer Protocol) logs contain valuable information about file transfers performed across a network. Security analysts can use these logs to review login attempts, monitor uploaded and downloaded files, identify unusual commands, and detect potentially unauthorized activity.

Splunk SIEM helps security teams collect, search, analyze, and monitor FTP events from a centralized platform.

## Project Overview

In this project, you will upload a sample FTP log file into Splunk SIEM and perform basic security analysis. You will learn how to identify active users, source IP addresses, FTP commands, transferred files, failed login attempts, and unusual file-transfer activity.

## Prerequisites

Before analyzing FTP logs in Splunk, ensure the following:

- Splunk Enterprise is installed and configured.
- You can access the Splunk Web interface.
- A sample FTP log file is available.
- You have permission to upload data into Splunk.
- The log file contains details such as timestamps, source IP addresses, usernames, FTP commands, filenames, and server responses.

## Steps to Upload Sample FTP Log Files to Splunk SIEM

### 1. Prepare the Sample FTP Log File

- Obtain a sample [FTP log file](https://www.secrepo.com/maccdc2012/ftp.log.gz) in a supported format such as `.log`, `.txt`, or `.csv`.
- Extract the downloaded `.gz` file if required.
- Confirm that the file contains valid FTP events.
- Check whether the logs include timestamps, source IP addresses, usernames, FTP commands, filenames, and response codes.
- Save the file in a location accessible from the system running Splunk.

### 2. Upload the Log File to Splunk

- Log in to the Splunk Web interface.
- Navigate to **Settings** > **Add Data**.
- Select **Upload** as the data input method.

### 3. Choose the FTP Log File

- Click **Select File**.
- Locate and select the prepared FTP log file.
- Click **Next** to continue.

### 4. Set the Source Type

- Open the **Set Source Type** section.
- Review how Splunk displays and separates the events.
- Select an existing FTP source type or create a custom source type.
- For this project, use `ftp_sample`.

### 5. Review the Input Settings

- Set the index to `ftp_logs`.
- Enter a suitable host name for the system that generated the logs.
- Keep the detected file name as the source.
- Confirm that the source type is `ftp_sample`.
- Ensure that all settings match the uploaded FTP log file.

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
index=ftp_logs sourcetype=ftp_sample
```

If you used a different index or source type, replace `ftp_logs` and `ftp_sample` with the correct values.

To check the total number of uploaded events, run:

```spl
index=ftp_logs sourcetype=ftp_sample
| stats count AS total_ftp_events
```

## Steps to Analyze FTP Log Files in Splunk SIEM

### 1. Search for FTP Events

- Open the Splunk Search application.
- Enter the following query to display all uploaded FTP events:

```spl
index=ftp_logs sourcetype=ftp_sample
```

### 2. Extract Relevant FTP Information

- Identify important FTP fields such as timestamp, source IP, username, command, file path, and server response.
- Check the **Interesting Fields** section in Splunk before manually extracting fields. Your source type may already provide them.
- If the events follow the expected text format, use the following example extraction query:

```spl
index=ftp_logs sourcetype=ftp_sample
| rex field=_raw "^(?<event_timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(?<src_ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?<username>[A-Za-z0-9_.-]+).*?(?<ftp_command>[A-Z]{3,5})(?:\s+(?<file_path>/[^\s]+))?"
| table _time event_timestamp src_ip username ftp_command file_path
```

The regular expression attempts to extract:

- `event_timestamp`: Date and time of the FTP event
- `src_ip`: Source IP address that initiated the connection
- `username`: Account used during the FTP session
- `ftp_command`: FTP command such as `USER`, `PASS`, `RETR`, or `STOR`
- `file_path`: File or directory involved in the activity

Log formats are different across FTP servers. Adjust the expression if the fields do not match your data.

### 3. Analyze File Transfer Activity

- Review the most commonly used FTP commands:

```spl
index=ftp_logs sourcetype=ftp_sample
| stats count AS command_count BY ftp_command
| sort - command_count
```

- Identify the source IP addresses generating the most FTP activity:

```spl
index=ftp_logs sourcetype=ftp_sample
| top limit=10 src_ip
```

- Identify the users performing the most FTP actions:

```spl
index=ftp_logs sourcetype=ftp_sample
| top limit=10 username
```

- Review uploaded and downloaded files. `STOR` normally represents an upload, while `RETR` normally represents a download:

```spl
index=ftp_logs sourcetype=ftp_sample ftp_command IN (STOR, RETR)
| stats count AS transfer_count BY src_ip username ftp_command file_path
| sort - transfer_count
```

If your logs use different field names, replace `src_ip`, `username`, `ftp_command`, and `file_path` with the fields available in your data.

### 4. Detect Anomalies

- Look for sudden increases or unusual changes in FTP activity.
- Run the following query to display FTP event volume in five-minute intervals:

```spl
index=ftp_logs sourcetype=ftp_sample
| timechart span=5m count AS ftp_events
```

- Search for potentially risky file types transferred through FTP:

```spl
index=ftp_logs sourcetype=ftp_sample ftp_command IN (STOR, RETR)
| where match(file_path, "(?i)\.(exe|dll|bat|cmd|ps1|zip|rar|7z)$")
| table _time src_ip username ftp_command file_path
```

- Identify source IP addresses performing a high number of FTP actions:

```spl
index=ftp_logs sourcetype=ftp_sample
| bin _time span=5m
| stats count AS ftp_event_count BY _time src_ip
| where ftp_event_count > 100
| sort - ftp_event_count
```

The value `100` is an example threshold. Adjust it according to the normal FTP activity in your environment.

### 5. Monitor User Behaviour

- Search the raw events for common FTP authentication-failure messages:

```spl
index=ftp_logs sourcetype=ftp_sample
| search _raw="*530*" OR _raw="*Login incorrect*" OR _raw="*authentication failed*"
| stats count AS failed_logins BY src_ip username
| sort - failed_logins
```

- Identify accounts or source IP addresses with repeated failed login attempts:

```spl
index=ftp_logs sourcetype=ftp_sample
| search _raw="*530*" OR _raw="*Login incorrect*" OR _raw="*authentication failed*"
| stats count AS failed_attempts BY src_ip username
| where failed_attempts >= 5
| sort - failed_attempts
```

- Review all activity associated with a user under investigation:

```spl
index=ftp_logs sourcetype=ftp_sample username="suspected_user"
| table _time src_ip username ftp_command file_path
| sort _time
```

Replace `suspected_user` with the account being investigated. Correlate suspicious FTP activity with firewall, endpoint, authentication, and file-integrity logs before making a final decision.

## Conclusion

Analyzing FTP logs using Splunk SIEM helps security professionals understand file-transfer activity and identify potential security threats. By monitoring login attempts, active users, source IP addresses, transferred files, unusual commands, and traffic spikes, analysts can detect abnormal behaviour and investigate possible incidents.

The searches and detection thresholds used in this project can be customized according to the FTP server, available log format, network size, and normal activity of the environment.

Happy analyzing!
