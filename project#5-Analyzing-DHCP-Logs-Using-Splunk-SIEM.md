# Analyzing DHCP Log Files Using Splunk SIEM

## Introduction

DHCP (Dynamic Host Configuration Protocol) logs record how IP addresses are assigned to devices on a network. These logs can include requested and leased IP addresses, MAC addresses, hostnames, lease activity, and DHCP server responses.

Security analysts can use DHCP logs to connect an IP address to a device, identify unknown systems, investigate repeated address requests, and detect unusual DHCP activity. Splunk SIEM provides a centralized platform for searching, analyzing, and monitoring these events.

## Project Overview

In this project, you will upload a sample DHCP log file into Splunk SIEM and perform basic security analysis. You will learn how to review IP address assignments, active clients, lease activity, DHCP traffic spikes, and potentially unauthorized devices.

## Prerequisites

Before analyzing DHCP logs in Splunk, ensure the following:

- Splunk Enterprise is installed and configured.
- You can access the Splunk Web interface.
- A sample DHCP log file is available.
- You have permission to upload data into Splunk.
- The log contains details such as timestamps, IP addresses, MAC addresses, hostnames, message types, and lease events.

## Steps to Upload Sample DHCP Log Files to Splunk SIEM

### 1. Prepare the Sample DHCP Log File

- Obtain a sample [DHCP log file](https://www.secrepo.com/maccdc2012/dhcp.log.gz) in a supported format such as `.log`, `.txt`, or `.csv`.
- Extract the downloaded `.gz` file if required.
- Confirm that the file contains valid DHCP events.
- Check whether the logs include timestamps, leased IP addresses, MAC addresses, client identifiers, hostnames, and DHCP message types.
- Save the file in a location accessible from the system running Splunk.

### 2. Upload the Log File to Splunk

- Log in to the Splunk Web interface.
- Navigate to **Settings** > **Add Data**.
- Select **Upload** as the data input method.

### 3. Choose the DHCP Log File

- Click **Select File**.
- Locate and select the prepared DHCP log file.
- Click **Next** to continue.

### 4. Set the Source Type

- Open the **Set Source Type** section.
- Review how Splunk displays and separates the events.
- Select an existing DHCP source type or create a custom source type.
- For this project, use `dhcp_sample`.

### 5. Review the Input Settings

- Set the index to `dhcp_logs`.
- Enter a suitable host name for the DHCP server that generated the logs.
- Keep the detected file name as the source.
- Confirm that the source type is `dhcp_sample`.
- Ensure that all settings match the uploaded DHCP log file.

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
index=dhcp_logs sourcetype=dhcp_sample
```

If you used a different index or source type, replace `dhcp_logs` and `dhcp_sample` with the correct values.

To check the total number of uploaded events, run:

```spl
index=dhcp_logs sourcetype=dhcp_sample
| stats count AS total_dhcp_events
```

## Steps to Analyze DHCP Log Files in Splunk SIEM

### 1. Search for DHCP Events

- Open the Splunk Search application.
- Enter the following query to display all uploaded DHCP events:

```spl
index=dhcp_logs sourcetype=dhcp_sample
```

### 2. Extract Relevant DHCP Information

- Identify important DHCP fields such as leased IP, client MAC address, hostname, message type, and DHCP server.
- Check the **Interesting Fields** section in Splunk before manually extracting fields.
- For common DHCP messages, use the following example extraction:

```spl
index=dhcp_logs sourcetype=dhcp_sample
| rex field=_raw "(?<dhcp_message>DHCPDISCOVER|DHCPOFFER|DHCPREQUEST|DHCPACK|DHCPNAK|DHCPRELEASE)"
| rex field=_raw "(?:on|for)\s+(?<leased_ip>\d{1,3}(?:\.\d{1,3}){3})"
| rex field=_raw "(?:from|to)\s+(?<client_mac>[0-9A-Fa-f:.-]{11,17})"
| table _time dhcp_message leased_ip client_mac host
```

Common field names include:

- `leased_ip`, `assigned_ip`, or `dest_ip`
- `client_mac`, `mac`, or `client_identifier`
- `hostname` or `client_hostname`
- `dhcp_message`, `message_type`, or `action`

DHCP log formats are different across Windows, Linux, and network appliances. Adjust the expression or field names if they do not match your data.

### 3. Analyze IP Address Assignment Patterns

- Count how often each IP address appears in the DHCP logs:

```spl
index=dhcp_logs sourcetype=dhcp_sample
| stats count AS event_count BY leased_ip
| sort - event_count
```

- Identify the most frequently leased IP addresses:

```spl
index=dhcp_logs sourcetype=dhcp_sample
| top limit=10 leased_ip
```

- Identify the most active client devices:

```spl
index=dhcp_logs sourcetype=dhcp_sample
| top limit=10 client_mac
```

- Connect each client device with its observed IP addresses:

```spl
index=dhcp_logs sourcetype=dhcp_sample
| stats values(leased_ip) AS observed_ips count AS dhcp_events BY client_mac
| sort - dhcp_events
```

### 4. Detect Anomalies

- Look for sudden increases or unusual changes in DHCP traffic:

```spl
index=dhcp_logs sourcetype=dhcp_sample
| timechart span=5m count AS dhcp_events
```

- Identify clients requesting many different IP addresses:

```spl
index=dhcp_logs sourcetype=dhcp_sample
| stats dc(leased_ip) AS unique_ips values(leased_ip) AS observed_ips BY client_mac
| where unique_ips >= 5
| sort - unique_ips
```

- Search for DHCP negative acknowledgements, which indicate that a requested address could not be used:

```spl
index=dhcp_logs sourcetype=dhcp_sample (dhcp_message="DHCPNAK" OR "DHCPNAK")
| stats count AS nak_count BY client_mac leased_ip
| sort - nak_count
```

- Compare client devices with an approved MAC-address list when an allowlist lookup is available:

```spl
index=dhcp_logs sourcetype=dhcp_sample client_mac=*
| lookup authorized_devices.csv client_mac OUTPUT device_name AS approved_device
| where isnull(approved_device)
| stats count AS dhcp_events values(leased_ip) AS observed_ips BY client_mac
| sort - dhcp_events
```

The last search requires a lookup file named `authorized_devices.csv` containing a `client_mac` column.

### 5. Monitor IP Address Usage

- Review when each IP address was first and last observed:

```spl
index=dhcp_logs sourcetype=dhcp_sample leased_ip=*
| stats earliest(_time) AS first_seen latest(_time) AS last_seen count AS event_count BY leased_ip client_mac
| convert ctime(first_seen) ctime(last_seen)
| sort - event_count
```

- Identify IP addresses associated with more than one MAC address:

```spl
index=dhcp_logs sourcetype=dhcp_sample leased_ip=* client_mac=*
| stats dc(client_mac) AS mac_count values(client_mac) AS client_macs BY leased_ip
| where mac_count > 1
| sort - mac_count
```

- Review DHCP activity for a device under investigation:

```spl
index=dhcp_logs sourcetype=dhcp_sample client_mac="00:11:22:33:44:55"
| table _time client_mac leased_ip hostname dhcp_message
| sort _time
```

Replace `00:11:22:33:44:55` with the MAC address under investigation. Multiple IP addresses or MAC addresses are not automatically malicious because lease reuse and network movement can be normal. Correlate suspicious DHCP events with switch, wireless, firewall, endpoint, and asset-inventory data before making a final decision.

## Conclusion

Analyzing DHCP logs using Splunk SIEM helps security professionals understand IP address assignments and connect network activity to individual devices. By monitoring leased addresses, client identifiers, DHCP traffic spikes, negative acknowledgements, and unknown devices, analysts can detect abnormal behaviour and support incident investigations.

The searches and detection thresholds used in this project can be customized according to the DHCP server, log format, network size, address pool, and normal activity of the environment.

Happy analyzing!
