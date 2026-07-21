# Analyzing SSH Log Files Using Splunk SIEM

## Introduction

SSH (Secure Shell) logs record remote access activity on Linux and Unix systems. These logs can contain successful and failed login attempts, usernames, source IP addresses, authentication methods, and session details.

Security analysts can use SSH logs to detect brute-force attempts, unauthorized access, unusual login sources, and compromised accounts. Splunk SIEM provides a centralized platform for searching, analyzing, and monitoring these events.

## Project Overview

In this project, you will upload a sample SSH log file into Splunk SIEM and perform basic security analysis. You will learn how to identify successful and failed logins, active users, source IP addresses, authentication spikes, and suspicious remote-access activity.

## Prerequisites

Before analyzing SSH logs in Splunk, ensure the following:

- Splunk Enterprise is installed and configured.
- You can access the Splunk Web interface.
- A sample SSH or Linux authentication log file is available.
- You have permission to upload data into Splunk.
- The log contains details such as timestamps, usernames, source IP addresses, ports, and authentication results.

## Steps to Upload Sample SSH Log Files to Splunk SIEM

### 1. Prepare the Sample SSH Log File

- Obtain a sample [SSH log file](https://www.secrepo.com/maccdc2012/ssh.log.gz) in a supported format such as `.log`, `.txt`, or `.csv`.
- Extract the downloaded `.gz` file if required.
- Confirm that the file contains valid SSH or authentication events.
- Check whether the logs include timestamps, source IP addresses, usernames, login results, and session information.
- Save the file in a location accessible from the system running Splunk.

### 2. Upload the Log File to Splunk

- Log in to the Splunk Web interface.
- Navigate to **Settings** > **Add Data**.
- Select **Upload** as the data input method.

### 3. Choose the SSH Log File

- Click **Select File**.
- Locate and select the prepared SSH log file.
- Click **Next** to continue.

### 4. Set the Source Type

- Open the **Set Source Type** section.
- Review how Splunk displays and separates the events.
- Select an existing SSH or syslog source type, or create a custom source type.
- For this project, use `ssh_sample`.

### 5. Review the Input Settings

- Set the index to `ssh_logs`.
- Enter a suitable host name for the server that generated the logs.
- Keep the detected file name as the source.
- Confirm that the source type is `ssh_sample`.
- Ensure that all settings match the uploaded SSH log file.

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
index=ssh_logs sourcetype=ssh_sample
```

If you used a different index or source type, replace `ssh_logs` and `ssh_sample` with the correct values.

To check the total number of uploaded events, run:

```spl
index=ssh_logs sourcetype=ssh_sample
| stats count AS total_ssh_events
```

## Steps to Analyze SSH Log Files in Splunk SIEM

### 1. Search for SSH Events

- Open the Splunk Search application.
- Enter the following query to display all uploaded SSH events:

```spl
index=ssh_logs sourcetype=ssh_sample
```

### 2. Extract Relevant SSH Information

- Identify important fields such as username, source IP, source port, authentication result, and authentication method.
- Check the **Interesting Fields** section in Splunk before manually extracting fields.
- For common Linux SSH authentication messages, use this example extraction:

```spl
index=ssh_logs sourcetype=ssh_sample ("Accepted password" OR "Accepted publickey" OR "Failed password")
| rex field=_raw "(?<action>Accepted|Failed)\s+(?:password|publickey)\s+for\s+(?:invalid user\s+)?(?<user>\S+)\s+from\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?<src_port>\d+)"
| table _time action user src_ip src_port
```

The exact message format may differ across operating systems and SSH services. Adjust the expression or field names if they do not match your data.

### 3. Analyze SSH Activity Patterns

- Count successful and failed authentication attempts:

```spl
index=ssh_logs sourcetype=ssh_sample ("Accepted password" OR "Accepted publickey" OR "Failed password")
| eval action=case(match(_raw,"Accepted"),"success",match(_raw,"Failed"),"failed",true(),"other")
| stats count AS attempt_count BY action
```

- Identify the source IP addresses generating the most SSH activity:

```spl
index=ssh_logs sourcetype=ssh_sample
| top limit=10 src_ip
```

- Identify the usernames appearing most frequently:

```spl
index=ssh_logs sourcetype=ssh_sample
| top limit=10 user
```

- Review successful SSH logins:

```spl
index=ssh_logs sourcetype=ssh_sample ("Accepted password" OR "Accepted publickey")
| table _time host user src_ip src_port
| sort - _time
```

### 4. Detect Anomalies

- Look for sudden increases in SSH authentication activity:

```spl
index=ssh_logs sourcetype=ssh_sample
| timechart span=5m count AS ssh_events
```

- Identify possible brute-force activity by counting failed logins from each IP address:

```spl
index=ssh_logs sourcetype=ssh_sample "Failed password"
| stats count AS failed_attempts dc(user) AS targeted_users BY src_ip
| where failed_attempts >= 10
| sort - failed_attempts
```

- Identify successful logins that occurred after repeated failures from the same source IP:

```spl
index=ssh_logs sourcetype=ssh_sample ("Failed password" OR "Accepted password" OR "Accepted publickey")
| eval result=if(match(_raw,"Accepted"),"success","failure")
| stats count(eval(result="failure")) AS failures count(eval(result="success")) AS successes BY src_ip user
| where failures >= 5 AND successes > 0
| sort - failures
```

- Investigate a suspicious source IP address:

```spl
index=ssh_logs sourcetype=ssh_sample src_ip="192.0.2.10"
| table _time host user src_ip action
| sort _time
```

Replace `192.0.2.10` with the IP address under investigation. The thresholds are examples and should be adjusted to match normal activity.

### 5. Monitor User Behaviour

- Identify usernames targeted by repeated failed login attempts:

```spl
index=ssh_logs sourcetype=ssh_sample "Failed password"
| stats count AS failed_attempts dc(src_ip) AS source_count BY user
| where failed_attempts >= 5
| sort - failed_attempts
```

- Review activity for a specific account:

```spl
index=ssh_logs sourcetype=ssh_sample user="suspected_user"
| table _time host src_ip action src_port
| sort _time
```

- If the logs contain session-opened and session-closed events with a common session ID, calculate session duration:

```spl
index=ssh_logs sourcetype=ssh_sample session_id=*
| stats earliest(_time) AS session_start latest(_time) AS session_end BY user session_id src_ip
| eval session_duration_seconds=session_end-session_start
| table user src_ip session_id session_duration_seconds
```

Replace `suspected_user` with the account being investigated. Correlate suspicious SSH events with firewall, endpoint, identity, and system audit logs before making a final decision.

## Conclusion

Analyzing SSH logs using Splunk SIEM helps security professionals monitor remote access and detect potential threats. By reviewing successful and failed logins, active users, source IP addresses, authentication spikes, and brute-force patterns, analysts can identify abnormal behaviour and investigate possible unauthorized access.

The searches and detection thresholds used in this project can be customized according to the operating system, SSH service, log format, and normal remote-access activity of the environment.

Happy analyzing!
