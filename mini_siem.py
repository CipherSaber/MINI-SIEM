#!/usr/bin/env python3
"""
Mini-SIEM: A lightweight Security Information and Event Management system
"""

import re
import json
import pandas as pd
import matplotlib.pyplot as plt
import streamlit as st
from datetime import datetime, timedelta
import requests
from collections import defaultdict, Counter
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

class MiniSIEM:
    """Mini-SIEM: Real-Time Threat Monitoring Dashboard"""
    
    def __init__(self):
        self.threats = {
            'failed_logins': [],
            'root_attempts': [],
            'suspicious_ips': defaultdict(int),
            'sql_injections': [],
            'brute_force_attempts': defaultdict(list),
            'unusual_activities': []
        }
        
        # Threat detection patterns
        self.patterns = {
            'ssh_failed': r'Failed password for .* from (\\d+\\.\\d+\\.\\d+\\.\\d+)',
            'ssh_root': r'Failed password for root from (\\d+\\.\\d+\\.\\d+\\.\\d+)',
            'sql_injection': r'(\\\'|\\"|union|select|insert|update|delete|drop|script|alert).*?(\\\'|\\"|;)',
            'suspicious_user_agent': r'(sqlmap|nikto|nmap|masscan|dirb|gobuster)',
            'directory_traversal': r'\\.\\.[\\\\/]',
            'xss_attempt': r'(<script|javascript:|onload=|onerror=)',
            'command_injection': r'(\\||&&|;|`|\\$\\()'
        }
        
        self.geo_cache = {}
        
    def parse_auth_log(self, log_content):
        """Parse Linux auth.log for security events"""
        lines = log_content.split('\\n')
        
        for line in lines:
            if not line.strip():
                continue
                
            # Extract timestamp
            timestamp_match = re.search(r'(\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})', line)
            timestamp = timestamp_match.group(1) if timestamp_match else datetime.now().strftime('%b %d %H:%M:%S')
            
            # Failed SSH login attempts
            failed_match = re.search(self.patterns['ssh_failed'], line, re.IGNORECASE)
            if failed_match:
                ip = failed_match.group(1)
                self.threats['failed_logins'].append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'log_entry': line
                })
                self.threats['suspicious_ips'][ip] += 1
                self.threats['brute_force_attempts'][ip].append(timestamp)
            
            # Root login attempts
            root_match = re.search(self.patterns['ssh_root'], line, re.IGNORECASE)
            if root_match:
                ip = root_match.group(1)
                self.threats['root_attempts'].append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'log_entry': line
                })
                
    def parse_web_log(self, log_content):
        """Parse Apache/Nginx web logs for web-based attacks"""
        lines = log_content.split('\\n')
        
        for line in lines:
            if not line.strip():
                continue
            
            # Extract common log format components
            parts = line.split()
            if len(parts) < 7:
                continue
                
            ip = parts[0]
            timestamp = parts[3].lstrip('[') if len(parts) > 3 else datetime.now().strftime('%d/%b/%Y:%H:%M:%S')
            request = ' '.join(parts[5:8]) if len(parts) > 7 else ''
            user_agent = ' '.join(parts[11:]) if len(parts) > 11 else ''
            
            # SQL Injection detection
            if re.search(self.patterns['sql_injection'], request + user_agent, re.IGNORECASE):
                self.threats['sql_injections'].append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'request': request,
                    'user_agent': user_agent,
                    'log_entry': line
                })
                self.threats['suspicious_ips'][ip] += 1
            
            # Suspicious User Agent
            if re.search(self.patterns['suspicious_user_agent'], user_agent, re.IGNORECASE):
                self.threats['unusual_activities'].append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'type': 'Suspicious User Agent',
                    'details': user_agent,
                    'log_entry': line
                })
                self.threats['suspicious_ips'][ip] += 1
            
            # Directory Traversal
            if re.search(self.patterns['directory_traversal'], request, re.IGNORECASE):
                self.threats['unusual_activities'].append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'type': 'Directory Traversal',
                    'details': request,
                    'log_entry': line
                })
                self.threats['suspicious_ips'][ip] += 1
                
            # XSS Attempts
            if re.search(self.patterns['xss_attempt'], request, re.IGNORECASE):
                self.threats['unusual_activities'].append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'type': 'XSS Attempt',
                    'details': request,
                    'log_entry': line
                })
                self.threats['suspicious_ips'][ip] += 1
    
    def get_ip_geolocation(self, ip):
        """Get geolocation information for IP addresses"""
        if ip in self.geo_cache:
            return self.geo_cache[ip]
            
        try:
            # Using ipinfo.io free API (rate limited)
            response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=2)
            if response.status_code == 200:
                data = response.json()
                geo_info = {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'org': data.get('org', 'Unknown')
                }
                self.geo_cache[ip] = geo_info
                return geo_info
        except:
            pass
            
        self.geo_cache[ip] = {'country': 'Unknown', 'city': 'Unknown', 'org': 'Unknown'}
        return self.geo_cache[ip]
    
    def identify_brute_force(self, threshold=5, time_window=300):
        """Identify brute force attacks based on failed login frequency"""
        brute_force_ips = []
        
        for ip, attempts in self.threats['brute_force_attempts'].items():
            if len(attempts) >= threshold:
                # Check if attempts occurred within time window
                # For simplicity, we'll just check total count
                brute_force_ips.append({
                    'ip': ip,
                    'attempts': len(attempts),
                    'severity': 'High' if len(attempts) > 10 else 'Medium'
                })
        
        return brute_force_ips
    
    def generate_threat_report(self):
        """Generate comprehensive threat analysis report"""
        total_failed_logins = len(self.threats['failed_logins'])
        unique_ips = len(self.threats['suspicious_ips'])
        root_attempts = len(self.threats['root_attempts'])
        sql_injections = len(self.threats['sql_injections'])
        unusual_activities = len(self.threats['unusual_activities'])
        brute_force_attacks = len(self.identify_brute_force())
        
        report = f"""
=== Mini-SIEM Threat Analysis Report ===
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🚨 CRITICAL FINDINGS:
[!] {total_failed_logins} Failed login attempts detected
[!] {unique_ips} Unique suspicious IP addresses found
[!] {root_attempts} Root login attempts detected
[!] {sql_injections} SQL injection attempts found
[!] {unusual_activities} Other suspicious activities detected
[!] {brute_force_attacks} Potential brute force attacks identified

📊 TOP THREAT SOURCES:
"""
        
        # Top 5 suspicious IPs
        top_ips = sorted(self.threats['suspicious_ips'].items(), key=lambda x: x[1], reverse=True)[:5]
        for i, (ip, count) in enumerate(top_ips, 1):
            geo = self.get_ip_geolocation(ip)
            report += f"{i}. {ip} ({geo['country']}, {geo['city']}) - {count} incidents\\n"
        
        return report
    
    def create_visualizations(self):
        """Create threat visualization charts"""
        st.subheader("📊 Threat Analysis Dashboard")
        
        # Threat Summary Metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Failed Logins", len(self.threats['failed_logins']), 
                     delta=len(self.threats['failed_logins']) - 10 if len(self.threats['failed_logins']) > 10 else None)
        
        with col2:
            st.metric("Suspicious IPs", len(self.threats['suspicious_ips']), 
                     delta=len(self.threats['suspicious_ips']) - 5 if len(self.threats['suspicious_ips']) > 5 else None)
        
        with col3:
            st.metric("Root Attempts", len(self.threats['root_attempts']), 
                     delta=len(self.threats['root_attempts']) if len(self.threats['root_attempts']) > 0 else None)
        
        with col4:
            st.metric("SQL Injections", len(self.threats['sql_injections']), 
                     delta=len(self.threats['sql_injections']) if len(self.threats['sql_injections']) > 0 else None)
        
        # Top Suspicious IPs Chart
        if self.threats['suspicious_ips']:
            st.subheader("🎯 Top Suspicious IP Addresses")
            top_ips = dict(sorted(self.threats['suspicious_ips'].items(), key=lambda x: x[1], reverse=True)[:10])
            
            fig = px.bar(x=list(top_ips.keys()), y=list(top_ips.values()),
                        labels={'x': 'IP Address', 'y': 'Number of Incidents'},
                        title="Suspicious Activity by IP Address",
                        color=list(top_ips.values()),
                        color_continuous_scale='Reds')
            st.plotly_chart(fig, use_container_width=True)
        
        # Attack Types Distribution
        attack_types = {
            'Failed Logins': len(self.threats['failed_logins']),
            'Root Attempts': len(self.threats['root_attempts']),
            'SQL Injections': len(self.threats['sql_injections']),
            'Other Suspicious': len(self.threats['unusual_activities'])
        }
        
        if sum(attack_types.values()) > 0:
            st.subheader("🛡️ Attack Types Distribution")
            fig = px.pie(values=list(attack_types.values()), names=list(attack_types.keys()),
                        title="Distribution of Attack Types")
            st.plotly_chart(fig, use_container_width=True)
        
        # Geographic Distribution
        if self.threats['suspicious_ips']:
            st.subheader("🌍 Geographic Distribution of Threats")
            countries = defaultdict(int)
            for ip in self.threats['suspicious_ips'].keys():
                geo = self.get_ip_geolocation(ip)
                countries[geo['country']] += self.threats['suspicious_ips'][ip]
            
            if countries:
                fig = px.bar(x=list(countries.keys())[:10], y=list(countries.values())[:10],
                            labels={'x': 'Country', 'y': 'Number of Incidents'},
                            title="Threat Sources by Country")
                st.plotly_chart(fig, use_container_width=True)
        
        # Brute Force Analysis
        brute_force_attacks = self.identify_brute_force()
        if brute_force_attacks:
            st.subheader("💥 Brute Force Attack Analysis")
            bf_df = pd.DataFrame(brute_force_attacks)
            st.dataframe(bf_df, use_container_width=True)
    
    def export_results(self, filename="siem_threat_report.json"):
        """Export threat analysis results to JSON file"""
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_failed_logins': len(self.threats['failed_logins']),
                'unique_suspicious_ips': len(self.threats['suspicious_ips']),
                'root_attempts': len(self.threats['root_attempts']),
                'sql_injections': len(self.threats['sql_injections']),
                'unusual_activities': len(self.threats['unusual_activities'])
            },
            'threats': self.threats,
            'brute_force_analysis': self.identify_brute_force()
        }
        
        # Convert defaultdict to regular dict for JSON serialization
        export_data['threats']['suspicious_ips'] = dict(export_data['threats']['suspicious_ips'])
        export_data['threats']['brute_force_attempts'] = dict(export_data['threats']['brute_force_attempts'])
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        return filename