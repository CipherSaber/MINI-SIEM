import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
from mini_siem import MiniSIEM
from datetime import datetime
import time
from collections import defaultdict

# Configure Streamlit page
st.set_page_config(
    page_title="Mini-SIEM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #ff6b6b, #ee5a24);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .threat-card {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #dc3545;
        margin-bottom: 1rem;
    }
    .success-card {
        background-color: #d4edda;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #28a745;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

def main():
    # Main header
    st.markdown("""
    <div class="main-header">
        <h1> Mini-SIEM: Real-Time Threat Monitoring Dashboard</h1>
        <p>Security Information and Event Management System</p>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar
    st.sidebar.title("SIEM Controls")
    st.sidebar.markdown("---")

    # File upload section
    st.sidebar.subheader("📁 Log File Upload")
    auth_log_file = st.sidebar.file_uploader("Upload auth.log", type=['log', 'txt'])
    web_log_file = st.sidebar.file_uploader("Upload access.log", type=['log', 'txt'])

    # Analysis configuration
    st.sidebar.subheader(" Analysis Settings")
    brute_force_threshold = st.sidebar.slider("Brute Force Threshold", 1, 10, 3)
    time_window = st.sidebar.slider("Time Window (minutes)", 1, 60, 5)

    # Auto-refresh option
    auto_refresh = st.sidebar.checkbox("Auto Refresh (30s)")

    if auto_refresh:
        time.sleep(30)
        st.rerun()

    # Initialize SIEM
    siem = MiniSIEM()

    # Process uploaded files or use sample data
    auth_content = ""
    web_content = ""

    if auth_log_file is not None:
        auth_content = str(auth_log_file.read(), "utf-8")
    else:
        # Use sample data if no file uploaded
        try:
            with open('auth.log', 'r') as f:
                auth_content = f.read()
        except FileNotFoundError:
            st.warning("No auth.log file found. Please upload a file or ensure sample data exists.")

    if web_log_file is not None:
        web_content = str(web_log_file.read(), "utf-8")
    else:
        # Use sample data if no file uploaded
        try:
            with open('access.log', 'r') as f:
                web_content = f.read()
        except FileNotFoundError:
            st.warning("No access.log file found. Please upload a file or ensure sample data exists.")

    # Run analysis if we have data
    if auth_content or web_content:
        with st.spinner("🔍 Analyzing logs for threats..."):
            if auth_content:
                siem.parse_auth_log(auth_content)
            if web_content:
                siem.parse_web_log(web_content)

            # Display results
            display_dashboard(siem, brute_force_threshold)
    else:
        st.error("No log data available. Please upload files or ensure sample data exists.")

    # Footer
    st.markdown("---")
    st.markdown("**Mini-SIEM Dashboard** | Built with Python & Streamlit | For Educational Purposes")

def display_dashboard(siem, brute_force_threshold):
    """Display the main dashboard with threat analysis"""

    # Key Metrics
    st.subheader("🚨 Security Metrics Overview")

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        failed_logins = len(siem.threats['failed_logins'])
        st.metric(
            "Failed Logins", 
            failed_logins,
            delta=f"+{failed_logins}" if failed_logins > 0 else None,
            delta_color="inverse"
        )

    with col2:
        suspicious_ips = len(siem.threats['suspicious_ips'])
        st.metric(
            "Suspicious IPs", 
            suspicious_ips,
            delta=f"+{suspicious_ips}" if suspicious_ips > 0 else None,
            delta_color="inverse"
        )

    with col3:
        root_attempts = len(siem.threats['root_attempts'])
        st.metric(
            "Root Attempts", 
            root_attempts,
            delta=f"+{root_attempts}" if root_attempts > 0 else None,
            delta_color="inverse"
        )

    with col4:
        sql_injections = len(siem.threats['sql_injections'])
        st.metric(
            "SQL Injections", 
            sql_injections,
            delta=f"+{sql_injections}" if sql_injections > 0 else None,
            delta_color="inverse"
        )

    with col5:
        unusual_activities = len(siem.threats['unusual_activities'])
        st.metric(
            "Other Threats", 
            unusual_activities,
            delta=f"+{unusual_activities}" if unusual_activities > 0 else None,
            delta_color="inverse"
        )

    # Threat Visualizations
    col1, col2 = st.columns(2)

    with col1:
        # Top Suspicious IPs
        if siem.threats['suspicious_ips']:
            st.subheader("🎯 Top Suspicious IP Addresses")
            top_ips = dict(sorted(siem.threats['suspicious_ips'].items(), key=lambda x: x[1], reverse=True)[:10])

            fig = px.bar(
                x=list(top_ips.values()), 
                y=list(top_ips.keys()),
                orientation='h',
                labels={'x': 'Number of Incidents', 'y': 'IP Address'},
                title="Suspicious Activity by IP Address",
                color=list(top_ips.values()),
                color_continuous_scale='Reds'
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, width='stretch')

    with col2:
        # Attack Types Distribution
        attack_types = {
            'Failed Logins': len(siem.threats['failed_logins']),
            'Root Attempts': len(siem.threats['root_attempts']),
            'SQL Injections': len(siem.threats['sql_injections']),
            'Other Suspicious': len(siem.threats['unusual_activities'])
        }

        if sum(attack_types.values()) > 0:
            st.subheader("🛡️ Attack Types Distribution")
            fig = px.pie(
                values=list(attack_types.values()), 
                names=list(attack_types.keys()),
                title="Distribution of Attack Types",
                color_discrete_sequence=px.colors.sequential.Reds_r
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, width='stretch')

    # Brute Force Analysis
    brute_force_attacks = siem.identify_brute_force(threshold=brute_force_threshold)
    if brute_force_attacks:
        st.subheader("💥 Brute Force Attack Analysis")
        bf_df = pd.DataFrame(brute_force_attacks)

        # Color code by severity
        def highlight_severity(row):
            if row['severity'] == 'High':
                return ['background-color: #ffebee'] * len(row)
            elif row['severity'] == 'Medium':
                return ['background-color: #fff3e0'] * len(row)
            else:
                return [''] * len(row)

        styled_df = bf_df.style.apply(highlight_severity, axis=1)
        st.dataframe(styled_df, width='stretch')

    # Detailed Threat Analysis
    st.subheader("🔍 Detailed Threat Analysis")

    tab1, tab2, tab3, tab4 = st.tabs(["Failed Logins", "SQL Injections", "Root Attempts", "Other Threats"])

    with tab1:
        if siem.threats['failed_logins']:
            df = pd.DataFrame(siem.threats['failed_logins'])
            st.dataframe(df, width='stretch')
        else:
            st.info("No failed login attempts detected.")

    with tab2:
        if siem.threats['sql_injections']:
            df = pd.DataFrame(siem.threats['sql_injections'])
            st.dataframe(df, width='stretch')
        else:
            st.info("No SQL injection attempts detected.")

    with tab3:
        if siem.threats['root_attempts']:
            df = pd.DataFrame(siem.threats['root_attempts'])
            st.dataframe(df, width='stretch')
        else:
            st.info("No root login attempts detected.")

    with tab4:
        if siem.threats['unusual_activities']:
            df = pd.DataFrame(siem.threats['unusual_activities'])
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No other suspicious activities detected.")

    # Generate and display text report
    st.subheader("📋 Threat Analysis Report")
    with st.expander("View Detailed Report"):
        report = siem.generate_threat_report()
        st.text(report)

    # Export functionality
    st.subheader("💾 Export Results")
    col1, col2 = st.columns(2)

    with col1:
        if st.button("📄 Generate JSON Report"):
            filename = siem.export_results()
            st.success(f"Report exported to {filename}")

            # Provide download link
            with open(filename, 'r') as f:
                st.download_button(
                    label="⬇️ Download JSON Report",
                    data=f.read(),
                    file_name=filename,
                    mime="application/json"
                )

    with col2:
        if st.button("📊 Generate CSV Export"):
            # Create comprehensive CSV
            all_threats = []

            for threat in siem.threats['failed_logins']:
                all_threats.append({
                    'type': 'Failed Login',
                    'timestamp': threat['timestamp'],
                    'ip': threat['ip'],
                    'details': 'SSH login failure',
                    'log_entry': threat['log_entry']
                })

            for threat in siem.threats['sql_injections']:
                all_threats.append({
                    'type': 'SQL Injection',
                    'timestamp': threat['timestamp'],
                    'ip': threat['ip'],
                    'details': threat['request'],
                    'log_entry': threat['log_entry']
                })

            for threat in siem.threats['unusual_activities']:
                all_threats.append({
                    'type': threat['type'],
                    'timestamp': threat['timestamp'],
                    'ip': threat['ip'],
                    'details': threat['details'],
                    'log_entry': threat['log_entry']
                })

            if all_threats:
                df = pd.DataFrame(all_threats)
                csv = df.to_csv(index=False)
                st.download_button(
                    label="⬇️ Download CSV Report",
                    data=csv,
                    file_name="siem_threats_report.csv",
                    mime="text/csv"
                )
                st.success("CSV report generated successfully!")
            else:
                st.info("No threats detected to export.")

if __name__ == "__main__":
    main()
