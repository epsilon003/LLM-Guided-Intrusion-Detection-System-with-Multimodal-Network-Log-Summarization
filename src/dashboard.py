"""
LLM-Guided Explainable Intrusion Detection System
Module 4: Interactive Dashboard Interface
Run with: streamlit run dashboard.py
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json

# Configure page
st.set_page_config(
    page_title="IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem 0;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .alert-critical {
        background-color: #ff4444;
        color: white;
        padding: 1rem;
        border-radius: 0.5rem;
        font-weight: bold;
    }
    .alert-high {
        background-color: #ff9933;
        color: white;
        padding: 1rem;
        border-radius: 0.5rem;
        font-weight: bold;
    }
    .alert-medium {
        background-color: #ffcc00;
        color: black;
        padding: 1rem;
        border-radius: 0.5rem;
        font-weight: bold;
    }
    .alert-low {
        background-color: #66bb66;
        color: white;
        padding: 1rem;
        border-radius: 0.5rem;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


def initialize_session_state():
    """Initialize session state variables"""
    if 'alerts' not in st.session_state:
        st.session_state.alerts = []
    if 'detection_history' not in st.session_state:
        st.session_state.detection_history = []
    if 'models_loaded' not in st.session_state:
        st.session_state.models_loaded = False


def generate_sample_data(n_samples=100):
    """Generate sample detection data for demonstration"""
    np.random.seed(42)
    
    timestamps = [datetime.now() - timedelta(hours=i) for i in range(n_samples, 0, -1)]
    
    severities = np.random.choice(
        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NORMAL'],
        size=n_samples,
        p=[0.05, 0.15, 0.20, 0.25, 0.35]
    )
    
    attack_types = []
    for sev in severities:
        if sev == 'NORMAL':
            attack_types.append('Normal')
        else:
            attack_types.append(np.random.choice(['DoS', 'Probe', 'R2L', 'U2R']))
    
    confidences = []
    for sev in severities:
        if sev == 'CRITICAL':
            confidences.append(np.random.uniform(0.90, 1.0))
        elif sev == 'HIGH':
            confidences.append(np.random.uniform(0.75, 0.90))
        elif sev == 'MEDIUM':
            confidences.append(np.random.uniform(0.50, 0.75))
        elif sev == 'LOW':
            confidences.append(np.random.uniform(0.30, 0.50))
        else:
            confidences.append(np.random.uniform(0.0, 0.30))
    
    data = pd.DataFrame({
        'timestamp': timestamps,
        'severity': severities,
        'attack_type': attack_types,
        'confidence': confidences,
        'source_ip': [f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}" for _ in range(n_samples)],
        'destination_ip': [f"10.0.{np.random.randint(1,255)}.{np.random.randint(1,255)}" for _ in range(n_samples)],
        'model': np.random.choice(['Random Forest', 'Isolation Forest', 'DNN'], size=n_samples)
    })
    
    return data


def create_severity_chart(data):
    """Create severity distribution chart"""
    severity_counts = data['severity'].value_counts()
    
    colors = {
        'CRITICAL': '#ff4444',
        'HIGH': '#ff9933',
        'MEDIUM': '#ffcc00',
        'LOW': '#66bb66',
        'NORMAL': '#4da6ff'
    }
    
    fig = go.Figure(data=[
        go.Bar(
            x=severity_counts.index,
            y=severity_counts.values,
            marker_color=[colors.get(sev, '#cccccc') for sev in severity_counts.index]
        )
    ])
    
    fig.update_layout(
        title="Detection Severity Distribution",
        xaxis_title="Severity Level",
        yaxis_title="Count",
        height=400
    )
    
    return fig


def create_timeline_chart(data):
    """Create detection timeline chart"""
    hourly_data = data.groupby([pd.Grouper(key='timestamp', freq='H'), 'severity']).size().reset_index(name='count')
    
    fig = px.line(
        hourly_data,
        x='timestamp',
        y='count',
        color='severity',
        title='Detection Timeline (Last 24 Hours)',
        color_discrete_map={
            'CRITICAL': '#ff4444',
            'HIGH': '#ff9933',
            'MEDIUM': '#ffcc00',
            'LOW': '#66bb66',
            'NORMAL': '#4da6ff'
        }
    )
    
    fig.update_layout(height=400)
    return fig


def create_attack_type_chart(data):
    """Create attack type distribution pie chart"""
    attack_data = data[data['severity'] != 'NORMAL']
    attack_counts = attack_data['attack_type'].value_counts()
    
    fig = px.pie(
        values=attack_counts.values,
        names=attack_counts.index,
        title='Attack Type Distribution'
    )
    
    fig.update_layout(height=400)
    return fig


def main():
    """Main dashboard function"""
    initialize_session_state()
    
    # Header
    st.markdown('<div class="main-header">🛡️ LLM-Guided Intrusion Detection System</div>', unsafe_allow_html=True)
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Model selection
        st.subheader("Detection Model")
        model_choice = st.selectbox(
            "Select Model",
            ["Random Forest", "Isolation Forest", "Deep Neural Network"]
        )
        
        # LLM backend
        st.subheader("LLM Backend")
        llm_backend = st.selectbox(
            "Select LLM",
            ["Template (No API)", "OpenAI GPT-4", "Anthropic Claude"]
        )
        
        if llm_backend != "Template (No API)":
            api_key = st.text_input("API Key", type="password")
        
        # Threshold settings
        st.subheader("Detection Threshold")
        confidence_threshold = st.slider(
            "Minimum Confidence",
            min_value=0.0,
            max_value=1.0,
            value=0.5,
            step=0.05
        )
        
        st.markdown("---")
        
        # Actions
        st.subheader("Actions")
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.rerun()
        
        if st.button("📥 Load Sample Data", use_container_width=True):
            st.session_state.detection_history = generate_sample_data(100)
            st.success("Sample data loaded!")
            st.rerun()
        
        if st.button("🗑️ Clear All Data", use_container_width=True):
            st.session_state.detection_history = []
            st.session_state.alerts = []
            st.success("Data cleared!")
            st.rerun()
    
    # Main content
    if len(st.session_state.detection_history) == 0:
        st.info("👈 Click 'Load Sample Data' in the sidebar to get started!")
        return
    
    data = st.session_state.detection_history
    
    # Key metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        total_detections = len(data)
        st.metric("Total Detections", total_detections)
    
    with col2:
        anomalies = len(data[data['severity'] != 'NORMAL'])
        st.metric("Anomalies", anomalies, delta=f"{(anomalies/total_detections)*100:.1f}%")
    
    with col3:
        critical = len(data[data['severity'] == 'CRITICAL'])
        st.metric("Critical", critical, delta="⚠️" if critical > 0 else "✓")
    
    with col4:
        avg_confidence = data['confidence'].mean()
        st.metric("Avg Confidence", f"{avg_confidence:.2%}")
    
    with col5:
        active_model = model_choice
        st.metric("Active Model", active_model)
    
    st.markdown("---")
    
    # Charts row
    col1, col2 = st.columns(2)
    
    with col1:
        st.plotly_chart(create_severity_chart(data), use_container_width=True)
    
    with col2:
        st.plotly_chart(create_timeline_chart(data), use_container_width=True)
    
    # Attack distribution
    if len(data[data['severity'] != 'NORMAL']) > 0:
        st.plotly_chart(create_attack_type_chart(data), use_container_width=True)
    
    st.markdown("---")
    
    # Recent alerts
    st.header("🚨 Recent Alerts")
    
    # Filter controls
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity_filter = st.multiselect(
            "Filter by Severity",
            ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NORMAL'],
            default=['CRITICAL', 'HIGH']
        )
    
    with col2:
        attack_filter = st.multiselect(
            "Filter by Attack Type",
            data['attack_type'].unique(),
            default=data['attack_type'].unique()
        )
    
    with col3:
        time_range = st.selectbox(
            "Time Range",
            ["Last 1 Hour", "Last 6 Hours", "Last 24 Hours", "All Time"]
        )
    
    # Apply filters
    filtered_data = data[
        (data['severity'].isin(severity_filter)) &
        (data['attack_type'].isin(attack_filter))
    ]
    
    # Time filter
    if time_range == "Last 1 Hour":
        cutoff = datetime.now() - timedelta(hours=1)
        filtered_data = filtered_data[filtered_data['timestamp'] > cutoff]
    elif time_range == "Last 6 Hours":
        cutoff = datetime.now() - timedelta(hours=6)
        filtered_data = filtered_data[filtered_data['timestamp'] > cutoff]
    elif time_range == "Last 24 Hours":
        cutoff = datetime.now() - timedelta(hours=24)
        filtered_data = filtered_data[filtered_data['timestamp'] > cutoff]
    
    # Display alerts
    if len(filtered_data) == 0:
        st.info("No alerts match the current filters.")
    else:
        for idx, row in filtered_data.head(10).iterrows():
            severity_class = f"alert-{row['severity'].lower()}"
            
            with st.expander(
                f"🔔 {row['severity']} - {row['attack_type']} | {row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}",
                expanded=(row['severity'] in ['CRITICAL', 'HIGH'])
            ):
                col1, col2 = st.columns([1, 2])
                
                with col1:
                    st.write("**Detection Details:**")
                    st.write(f"- Severity: `{row['severity']}`")
                    st.write(f"- Confidence: `{row['confidence']:.2%}`")
                    st.write(f"- Model: `{row['model']}`")
                    st.write(f"- Source IP: `{row['source_ip']}`")
                    st.write(f"- Dest IP: `{row['destination_ip']}`")
                
                with col2:
                    st.write("**Explanation:**")
                    
                    # Generate explanation based on attack type
                    if row['attack_type'] == 'DoS':
                        explanation = f"""
                        A Denial of Service (DoS) attack has been detected with {row['confidence']:.0%} confidence.
                        The attack is attempting to overwhelm system resources from {row['source_ip']}.
                        
                        **Recommended Actions:**
                        - Block source IP immediately
                        - Enable rate limiting
                        - Investigate affected services
                        """
                    elif row['attack_type'] == 'Probe':
                        explanation = f"""
                        Network scanning activity detected from {row['source_ip']}. 
                        This appears to be reconnaissance activity with {row['confidence']:.0%} confidence.
                        
                        **Recommended Actions:**
                        - Monitor source IP for further activity
                        - Review firewall rules
                        - Check for vulnerable services
                        """
                    elif row['attack_type'] == 'R2L':
                        explanation = f"""
                        Remote-to-Local attack attempt detected with {row['confidence']:.0%} confidence.
                        Unauthorized access attempt from {row['source_ip']}.
                        
                        **Recommended Actions:**
                        - Block source IP immediately
                        - Review authentication logs
                        - Check for compromised credentials
                        """
                    elif row['attack_type'] == 'U2R':
                        explanation = f"""
                        Privilege escalation attempt detected with {row['confidence']:.0%} confidence.
                        Potential User-to-Root attack in progress.
                        
                        **Recommended Actions:**
                        - Investigate affected system immediately
                        - Review user permissions
                        - Check for exploit attempts
                        """
                    else:
                        explanation = "Normal network traffic. No action required."
                    
                    st.write(explanation)
                
                # Action buttons
                col1, col2, col3 = st.columns(3)
                with col1:
                    if st.button("✓ Acknowledge", key=f"ack_{idx}"):
                        st.success("Alert acknowledged")
                with col2:
                    if st.button("🚫 Block IP", key=f"block_{idx}"):
                        st.success(f"Blocked {row['source_ip']}")
                with col3:
                    if st.button("📄 Export", key=f"export_{idx}"):
                        st.info("Exporting alert details...")
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: gray;'>"
        "LLM-Guided Explainable IDS | Powered by AI & Machine Learning"
        "</div>",
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()