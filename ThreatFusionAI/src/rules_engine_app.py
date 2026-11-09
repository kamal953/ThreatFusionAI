import streamlit as st
import pandas as pd
from datetime import timedelta

st.set_page_config(page_title="Rule Engine Threat Detection", layout="wide")
st.title("Rule Engine - Threat Detection Dashboard")

# Upload CSV file
uploaded_file = st.file_uploader("Upload your CloudWatch Traffic CSV", type="csv")

if uploaded_file:
    try:
        # Read file and parse creation_time column
        df = pd.read_csv(uploaded_file)

        if 'creation_time' not in df.columns:
            st.error("'creation_time' column not found in CSV. Please upload the correct file.")
        else:
            df['creation_time'] = pd.to_datetime(df['creation_time'], errors='coerce')
            df = df.dropna(subset=['creation_time'])
            df.sort_values("creation_time", inplace=True)

            st.success(f"File loaded successfully with {df.shape[0]} rows!")

            # Configs
            malicious_ips = ["165.225.33.6", "147.161.161.82"]
            standard_ports = [80, 443, 22, 21, 25]

            alerts = []

            def log_alert(rule, ip, timestamp, message):
                alerts.append({
                    "Rule": rule,
                    "Source IP": ip,
                    "Timestamp": str(timestamp),
                    "Details": message
                })

            # Rule 1: Frequency Spike
            for ip, group in df.groupby("src_ip"):
                times = group["creation_time"].tolist()
                for i in range(len(times)):
                    count = 1
                    for j in range(i + 1, len(times)):
                        if times[j] - times[i] <= timedelta(seconds=60):
                            count += 1
                        else:
                            break
                    if count > 10:
                        log_alert("Frequency Spike", ip, times[i], f"{count} connections in 1 min")
                        break

            # Rule 2: Foreign Access to Prod
            if 'observation_name' in df.columns and 'src_ip_country_code' in df.columns:
                prod_df = df[df["observation_name"].str.contains("prod", case=False, na=False)]
                foreign_prod_df = prod_df[prod_df["src_ip_country_code"] != "IN"]
                for _, row in foreign_prod_df.iterrows():
                    log_alert("Foreign Access to Prod", row["src_ip"], row["creation_time"],
                              f"{row['src_ip_country_code']} IP accessed prod server {row['dst_ip']}")

            # Rule 3: Impossible Travel
            if 'src_ip_country_code' in df.columns:
                ip_time_country = df[["src_ip", "creation_time", "src_ip_country_code"]].drop_duplicates()
                for ip, group in ip_time_country.groupby("src_ip"):
                    for i in range(len(group) - 1):
                        row1 = group.iloc[i]
                        row2 = group.iloc[i + 1]
                        time_diff = abs((row2["creation_time"] - row1["creation_time"]).total_seconds())
                        if row1["src_ip_country_code"] != row2["src_ip_country_code"] and time_diff <= 30:
                            log_alert("Impossible Travel", ip, row2["creation_time"],
                                      f"{ip} appeared in {row1['src_ip_country_code']} and {row2['src_ip_country_code']} within {int(time_diff)} sec")
                            break

            # Rule 4: Weekend Activity
            df["weekday"] = df["creation_time"].dt.dayofweek
            weekend_df = df[df["weekday"] >= 5]
            for _, row in weekend_df.iterrows():
                log_alert("Weekend Activity", row["src_ip"], row["creation_time"],
                          f"Connection on {row['creation_time'].strftime('%A')}")

            # Rule 5: Unknown Port
            if 'dst_port' in df.columns:
                unknown_ports_df = df[~df["dst_port"].isin(standard_ports)]
                for _, row in unknown_ports_df.iterrows():
                    log_alert("Unknown Port", row["src_ip"], row["creation_time"],
                              f"Connected to port {row['dst_port']}")

            # Rule 6: Large Payload
            if 'bytes_out' in df.columns:
                large_df = df[df["bytes_out"] > 10_000_000]
                for _, row in large_df.iterrows():
                    log_alert("Large Payload", row["src_ip"], row["creation_time"],
                              f"Sent {row['bytes_out']} bytes")

            # Rule 7: Threat Intel Match
            ti_df = df[df["src_ip"].isin(malicious_ips)]
            for _, row in ti_df.iterrows():
                log_alert("Threat Intel Match", row["src_ip"], row["creation_time"],
                          "Known malicious IP detected")

            # Rule 8: Port Scan
            if 'dst_port' in df.columns:
                scan_df = df.groupby(["src_ip", pd.Grouper(key="creation_time", freq="1min")])["dst_port"].nunique().reset_index()
                scan_df = scan_df[scan_df["dst_port"] > 3]
                for _, row in scan_df.iterrows():
                    log_alert("Port Scan", row["src_ip"], row["creation_time"],
                              f"Accessed {row['dst_port']} ports in 1 min")

            # Rule 9: Odd Hour Activity
            df["hour"] = df["creation_time"].dt.hour
            odd_df = df[(df["hour"] >= 2) & (df["hour"] < 4)]
            for _, row in odd_df.iterrows():
                log_alert("Odd Hour Activity", row["src_ip"], row["creation_time"],
                          f"Activity at {row['creation_time'].strftime('%H:%M')}")

            # Rule 10: Repeated Suspicious Rules
            if 'rule_names' in df.columns:
                suspicious_df = df[df["rule_names"].str.contains("Suspicious", case=False, na=False)]
                suspicious_count = suspicious_df.groupby(
                    ["src_ip", pd.Grouper(key="creation_time", freq="5min")]
                ).size().reset_index(name="count")
                suspicious_count = suspicious_count[suspicious_count["count"] > 5]
                for _, row in suspicious_count.iterrows():
                    log_alert("Repeated Suspicious Rules", row["src_ip"], row["creation_time"],
                              f"{row['count']} suspicious detections in 5 min")

            # Display alerts
            if alerts:
                alerts_df = pd.DataFrame(alerts)
                st.subheader("Detected Alerts")
                st.dataframe(alerts_df, use_container_width=True)

                csv = alerts_df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "Download Alerts CSV",
                    csv,
                    "alerts.csv",
                    "text/csv"
                )
            else:
                st.success("No alerts triggered from the current dataset.")

    except Exception as e:
        st.error(f"Something went wrong: {e}")
