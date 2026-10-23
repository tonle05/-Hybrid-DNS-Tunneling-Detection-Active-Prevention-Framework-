import streamlit as st
import json
import pandas as pd
import time
import os
import altair as alt

# Configure wide layout for the security monitoring dashboard
st.set_page_config(
    page_title="IDPS Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Set main dashboard header
st.title("🛡️ Real-Time DNS Tunneling Detection & Prevention System")
st.markdown("---")

TELEMETRY_FILE = "dns_telemetry.json"

# ==========================================
# THRESHOLD CONFIGURATIONS
# ==========================================
MAX_ABSOLUTE_VOLUME_LIMIT = 1000
MIN_TEMPORAL_SUSPICION_LEVEL = 20

def load_telemetry():
    """Read live telemetry data exported by the backend parsing engine"""
    if not os.path.exists(TELEMETRY_FILE):
        return {"blocked_ips": [], "volume_quota": {}, "ip_matrix": {}, "last_updated": "N/A"}
    try:
        with open(TELEMETRY_FILE, "r") as f:
            return json.load(f)
    except:
        return {"blocked_ips": [], "volume_quota": {}, "ip_matrix": {}, "last_updated": "N/A"}

# --- FETCH LIVE TELEMETRY DATA ---
data = load_telemetry()

# ==========================================
# SECTION 1: KPI METRICS CARDS
# ==========================================
col1, col2, col3 = st.columns(3)

with col1:
    total_blocked = len(data["blocked_ips"])
    st.metric(
        label="🚨 Currently Isolated IPs",
        value=total_blocked,
        delta=f"+{total_blocked} Active Threats" if total_blocked > 0 else "Network Secure",
        delta_color="inverse"
    )

with col2:
    # Calculate the total accumulated bytes across all tracked anomalies
    total_bytes = sum(data["volume_quota"].values())
    st.metric(
        label="📊 Total Cumulative Payload Volume",
        value=f"{total_bytes} B",
        delta="30s Sliding Window"
    )

with col3:
    st.metric(
        label="🕒 Last System Sync Time",
        value=data["last_updated"]
    )

st.markdown("---")

# ==========================================
# SECTION 2: GLOBAL STATUS OVERVIEW (Requirement 1b - Fixed Grouping & Filter)
# ==========================================
st.subheader("🌐 Network Status Overview")

# Initialize session state for timeline history if not already set
if "timeline_history" not in st.session_state:
    st.session_state["timeline_history"] = []

ip_matrix = data.get("ip_matrix", {})
if ip_matrix:
    current_time_str = time.strftime("%H:%M:%S")

    # Iterate through each monitored host IP and its associated metrics to determine risk levels and security states
    for host_ip, host_metrics in ip_matrix.items():
        vol = host_metrics.get("current_volume", 0)
        score = host_metrics.get("total_risk_score", 0)
        temporal = host_metrics.get("temporal_score", 0)

        # Classify the operational health state of each observed IP address based on defined thresholds and blocklist status
        if host_ip in data["blocked_ips"] or score >= 75:
            host_status = "Blocked"
            risk_level = 100
        elif score >= 40 or vol >= MAX_ABSOLUTE_VOLUME_LIMIT or temporal >= MIN_TEMPORAL_SUSPICION_LEVEL:
            host_status = "Warning"
            risk_level = 60
        else:
            host_status = "Normal"
            risk_level = 30

        # Calculate the 10-second time bin for grouping timeline data points
        parts = current_time_str.split(":")
        hour_min = f"{parts[0]}:{parts[1]}"
        seconds = int(parts[2])
        rounded_seconds = (seconds // 10) * 10
        time_bin = f"{hour_min}:{rounded_seconds:02d}"

        # Append the current host's telemetry data point to the session state timeline history for real-time plotting and filtering
        st.session_state["timeline_history"].append({
            "IP Address": host_ip,
            "Timestamp": current_time_str,
            "Time Interval": time_bin,
            "Risk Level": risk_level,
            "Security State": host_status
        })

    # To prevent unbounded growth of the timeline history, limit it to the most recent 3000 entries (equivalent to 10 minutes of data at 10-second intervals for up to 50 hosts)
    if len(st.session_state["timeline_history"]) > 3000:
        st.session_state["timeline_history"] = st.session_state["timeline_history"][-1500:]

    # Convert the session state timeline history into a DataFrame for plotting and apply a filter based on user-selected time intervals using a slider component
    df_hist = pd.DataFrame(st.session_state["timeline_history"])

    # Remove duplicate entries for the same IP and time interval, keeping only the latest one to ensure accurate plotting without overplotting issues
    df_hist = df_hist.drop_duplicates(subset=["IP Address", "Time Interval"], keep="last")

    # Extract the unique time intervals from the historical data to populate the options for the time range slider filter
    unique_intervals = sorted(list(df_hist["Time Interval"].unique()))

    # If there are multiple unique time intervals available, display a slider to allow the user to filter the displayed data points based on a selected time range. If only one interval is present, skip the slider and display all data points for that interval while showing a caption indicating the active monitoring window slot.
    if len(unique_intervals) > 1:
        start_time, end_time = st.select_slider(
            "Select Monitor Time Window Range Filter",
            options=unique_intervals,
            value=(unique_intervals[0], unique_intervals[-1]),
            key="soc_time_range_slider"
        )
        df_filtered = df_hist[(df_hist["Time Interval"] >= start_time) & (df_hist["Time Interval"] <= end_time)]
    else:
        df_filtered = df_hist
        if unique_intervals:
            st.caption(f"Active Monitoring Window Slot: **{unique_intervals[0]}**")

    # Define a color scale for the security states to be used in the Altair visualizations, ensuring consistent color coding across different chart layers for clear visual distinction between Normal, Warning, and Blocked states
    state_order = ["Normal", "Warning", "Blocked"]
    color_scale = alt.Scale(
        domain=state_order,
        range=["#2ca02c", "#ff7f0e", "#d62728"]
    )

    # Construct the base Altair chart with the filtered DataFrame, encoding the x-axis as the time intervals and preparing for layered visualizations of both bar and line charts to represent risk levels and security states across monitored hosts over time. The xOffset encoding is used to group bars by IP address within each time interval, while color encodings differentiate security states and individual IP addresses in the line layer for enhanced interpretability of the global network status overview.
    base_chart = alt.Chart(df_filtered).encode(
        x=alt.X("Time Interval:N", title="Timeline", axis=alt.Axis(labelAngle=0))
    )

    # Chart Layer 1: Grouped bar chart representing the risk level metrics tiers for each monitored host IP address, with color encoding to indicate the security state status (Normal, Warning, Blocked) and tooltips for detailed information on hover. The xOffset encoding is used to group bars by IP address within each time interval, allowing for clear visual comparison of risk levels across different hosts while maintaining the temporal context of the monitoring data.
    bars_layer = base_chart.mark_bar(size=18).encode(
        xOffset="IP Address:N",
        y=alt.Y("Risk Level:Q", title="Risk Score Metrics Tiers", scale=alt.Scale(domain=[0, 110])),
        color=alt.Color("Security State:N", scale=color_scale, title="Security State Status"),
        tooltip=["IP Address", "Timestamp", "Security State", "Risk Level"]
    )

    # Chart Layer 2: Line chart connecting risk level data points for each monitored host IP address, with color encoding to distinguish individual hosts and tooltips for detailed information on hover. The xOffset encoding is used to group the line segments by IP address within each time interval, providing a clear visual representation of risk trends across different hosts over time.
    lines_layer = base_chart.mark_line(point=alt.OverlayMarkDef(size=60, filled=True)).encode(
        xOffset="IP Address:N",
        y="Risk Level:Q",
        color=alt.Color("IP Address:N", title="Monitored Device IP"),
        tooltip=["IP Address", "Timestamp", "Risk Level"]
    )

    # Combine the bar and line layers into a single Altair chart, resolving the color scales independently for each layer to maintain clear visual distinction between security states in the bar chart and individual hosts in the line chart. The final layered plot is then rendered within the Streamlit dashboard with a specified height and responsive width to provide an interactive global network status overview for security analysts.
    final_global_plot = alt.layer(bars_layer, lines_layer).resolve_scale(
        color="independent"
    ).properties(height=280)

    st.altair_chart(final_global_plot, width='stretch')
else:
    st.info("Gathering multi-host perimeter data streams...")

st.markdown("---")

# ==========================================
# SECTION 3: GRAPH & DATA VISUALIZATION (Drill-down Feature - Requirement 1a)
# ==========================================
left_chart_col, right_table_col = st.columns([2, 1])

with left_chart_col:
    st.subheader("🎯 Host Analysis ")

    # Select box to route layout scope to a unique source IP
    observed_ips = list(ip_matrix.keys())
    if observed_ips:
        selected_ip = st.selectbox("Select Target Host IP for Forensic Investigation", options=observed_ips)

        if selected_ip:
            profile = ip_matrix[selected_ip]
            is_ip_isolated = selected_ip in data["blocked_ips"]
            computed_state = "Blocked" if is_ip_isolated else ("Warning" if profile["total_risk_score"] >= 40 else "Normal")

            # Sub-KPI layer for chosen internal host profile
            sub_c1, sub_c2, sub_c3 = st.columns(3)
            sub_c1.metric("Selected Host State", computed_state)
            sub_c2.metric("Total Risk Profile Score", f"{profile['total_risk_score']}/100")
            sub_c3.metric("Aggregated Volumetric Size", f"{profile['current_volume']} Bytes")

            # Interactive breakdown bar chart for the selected host across metrics layers
            st.markdown("#### Risk Vector Dimensional Evaluation")
            vector_df = pd.DataFrame({
                "Evaluation Layer": ["Lexical", "Temporal", "Volumetric"],
                "Layer Score": [
                    profile["lexical_score"],
                    profile["temporal_score"],
                    profile["volumetric_score"]
                ]
            })

            pie_chart = alt.Chart(vector_df).mark_arc(
                innerRadius=50
            ).encode(
                theta=alt.Theta(
                    field="Layer Score",
                    type="quantitative"
                ),
                color=alt.Color(
                    field="Evaluation Layer",
                    type="nominal",
                    legend=alt.Legend(title="Risk Components")
                ),
                tooltip=[
                    "Evaluation Layer",
                    "Layer Score"
                ]
            ).properties(
                height=300
            )

            st.altair_chart(pie_chart, width='stretch')

            # Map specific exfiltration domain targets specifically for the filtered IP address
            st.markdown("#### Mapped Exfiltration Domain Target Quantities")
            target_quota_data = []
            for entity_key, volume_bytes in data["volume_quota"].items():
                if entity_key.startswith(f"{selected_ip} ➔ "):
                    target_domain = entity_key.split(" ➔ ")[1]
                    target_quota_data.append({"Target Destination Domain": target_domain, "Volume (Bytes)": volume_bytes})

            if target_quota_data:
                specific_quota_df = pd.DataFrame(target_quota_data)
                domain_chart = alt.Chart(specific_quota_df).mark_bar(color="#1f77b4", size=40).encode(
                    x=alt.X("Target Destination Domain:N", axis=alt.Axis(labelAngle=0, title="Destination Root Domain")),
                    y=alt.Y("Volume (Bytes):Q", title="Volume (Bytes)")
                ).properties(height=250)
                st.altair_chart(domain_chart, width='stretch')
            else:
                st.info("No payload target extractions verified for this source IP context.")

            # Explicit threshold validation and policy indicators layout
            st.markdown("#### Operational Defense Compliance Safeguards")
            v_breached = profile["current_volume"] >= MAX_ABSOLUTE_VOLUME_LIMIT
            t_breached = profile["temporal_score"] >= MIN_TEMPORAL_SUSPICION_LEVEL

            tc1, tc2 = st.columns(2)
            tc1.markdown(fr"**Volumetric Quota Limit ($\ge$ {MAX_ABSOLUTE_VOLUME_LIMIT}B):** " + ("🔴 BREACHED" if v_breached else "🟢 COMPLIANT"))
            tc2.markdown(fr"**Temporal Frequency Limit ($\ge$ {MIN_TEMPORAL_SUSPICION_LEVEL}pts):** " + ("🔴 BREACHED" if t_breached else "🟢 COMPLIANT"))

            if is_ip_isolated:
                st.error(f"🛑 CRITICAL FIREWALL Isolation Status: Active rule is actively dropped at kernel level.")
    else:
        st.info("No anomalous data exfiltration or threshold-breaching traffic detected.")

with right_table_col:
    st.subheader("🚫 Active Network Blocklist")
    if data["blocked_ips"]:
        blocked_df = pd.DataFrame(data["blocked_ips"], columns=["Compromised Host IP Address"])
        # Render the isolated hosts database table
        st.dataframe(blocked_df, width='stretch')
        st.error("Critical Alert: Kernel-level iptables DROP chains are active for the isolated hosts above.")
    else:
        st.success("Internal perimeter is clean. No hosts are currently quarantined.")

# ==========================================
# SECTION 4: AUTOMATED REFRESH MECHANISM
# ==========================================
# Force Streamlit UI to re-run every 1 second to fetch live updates without polling lag
time.sleep(1)
st.rerun()