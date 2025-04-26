import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import numpy as np
import io

# Set page configuration
st.set_page_config(
    page_title="Cybersecurity Attacks Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS to improve the appearance
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        font-weight: 600;
        color: #1E3A8A;
        margin-top: 1rem;
        margin-bottom: 0.5rem;
    }
    .card {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #F3F4F6;
        margin-bottom: 1rem;
    }
    .info-text {
        font-size: 0.9rem;
        color: #4B5563;
    }
    .highlight {
        color: #DC2626;
        font-weight: 600;
    }
    .upload-section {
        padding: 1.5rem;
        border-radius: 0.5rem;
        background-color: #EFF6FF;
        margin-bottom: 1.5rem;
        border: 1px dashed #3B82F6;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<div class="main-header">🛡️ Cybersecurity Attacks Analytics Dashboard</div>', unsafe_allow_html=True)
st.markdown('Monitor, analyze, and respond to cybersecurity threats in real-time.')

# File upload section
st.markdown('<div class="upload-section">', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Upload Data Files</div>', unsafe_allow_html=True)

col1, col2 = st.columns(2)

with col1:
    attacks_file = st.file_uploader("Upload Cybersecurity Attacks CSV", type=['csv'], help="Upload your cybersecurity attacks data in CSV format")
    
    if attacks_file:
        st.success(f"Successfully uploaded: {attacks_file.name}")
    else:
        st.info("Please upload a CSV file containing cybersecurity attack data")

with col2:
    ports_file = st.file_uploader("Upload TCP Ports CSV", type=['csv'], help="Upload your TCP ports information in CSV format")
    
    if ports_file:
        st.success(f"Successfully uploaded: {ports_file.name}")
    else:
        st.info("Optional: Upload TCP ports information to enhance service identification")

st.markdown('</div>', unsafe_allow_html=True)

# Function to load and clean data
def process_data(attacks_df, ports_df=None):
    # Clean the attacks data
    attacks_df = attacks_df.dropna(subset=['Attack category', 'Source IP', 'Destination IP'])
    
    # Convert timestamp to datetime
    if 'Time' in attacks_df.columns:
        attacks_df['Time'] = attacks_df['Time'].apply(lambda x: 
            pd.to_datetime(x.split('-')[0], unit='s') if isinstance(x, str) and '-' in x 
            else pd.NaT)
    
    # Extract CVE from Attack Reference
    if 'Attack Reference' in attacks_df.columns:
        attacks_df['CVE'] = attacks_df['Attack Reference'].str.extract(r'(CVE \d{4}-\d+)')
    
    # Add service name based on destination port if ports_df is available
    if ports_df is not None and 'Destination Port' in attacks_df.columns:
        ports_dict = dict(zip(ports_df['Port'], ports_df['Service']))
        attacks_df['Service'] = attacks_df['Destination Port'].map(lambda x: ports_dict.get(x, "Unknown"))
    
    return attacks_df

# Main dashboard function
def display_dashboard(df):
    # Handle empty dataframe
    if df.empty:
        st.error("No data available. Please check the data source.")
        return
        
    # Create tabs for different views
    tab1, tab2, tab3, tab4 = st.tabs(["Overview", "Attack Analysis", "Network Traffic", "Data Explorer"])
    
    with tab1:
        # Overview metrics
        st.markdown('<div class="sub-header">Key Metrics</div>', unsafe_allow_html=True)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.metric("Total Attacks", f"{len(df)}")
            st.markdown('</div>', unsafe_allow_html=True)
            
        with col2:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.metric("Unique Attack Categories", f"{df['Attack category'].nunique()}")
            st.markdown('</div>', unsafe_allow_html=True)
            
        with col3:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.metric("Unique Source IPs", f"{df['Source IP'].nunique()}")
            st.markdown('</div>', unsafe_allow_html=True)
            
        with col4:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.metric("Unique Target IPs", f"{df['Destination IP'].nunique()}")
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Attack distribution by category
        st.markdown('<div class="sub-header">Attack Distribution</div>', unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            category_counts = df['Attack category'].value_counts().reset_index()
            category_counts.columns = ['Attack Category', 'Count']
            
            fig = px.pie(
                category_counts, 
                values='Count', 
                names='Attack Category',
                title='Attack Distribution by Category',
                color_discrete_sequence=px.colors.qualitative.Safe,
                hole=0.4
            )
            fig.update_layout(legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1))
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            protocol_counts = df['Protocol'].value_counts().reset_index()
            protocol_counts.columns = ['Protocol', 'Count']
            
            fig = px.bar(
                protocol_counts, 
                x='Protocol', 
                y='Count',
                title='Attacks by Protocol',
                color='Protocol',
                color_discrete_sequence=px.colors.qualitative.Bold
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Timeline of attacks
        if 'Time' in df.columns and not df['Time'].isna().all():
            st.markdown('<div class="sub-header">Attack Timeline</div>', unsafe_allow_html=True)
            
            # Group by day and count attacks
            df_time = df.copy()
            df_time['Date'] = df_time['Time'].dt.date
            timeline = df_time.groupby('Date').size().reset_index(name='Count')
            
            fig = px.line(
                timeline, 
                x='Date', 
                y='Count',
                title='Number of Attacks Over Time',
                markers=True
            )
            fig.update_layout(xaxis_title="Date", yaxis_title="Number of Attacks")
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        st.markdown('<div class="sub-header">Attack Analysis</div>', unsafe_allow_html=True)
        
        # Filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            selected_category = st.multiselect(
                "Select Attack Category",
                options=df['Attack category'].dropna().unique(),
                default=df['Attack category'].dropna().unique()[0] if not df['Attack category'].dropna().empty else None
            )
        
        with col2:
            selected_protocol = st.multiselect(
                "Select Protocol",
                options=df['Protocol'].dropna().unique(),
                default=None
            )
            
        with col3:
            selected_subcategory = st.multiselect(
                "Select Attack Subcategory",
                options=df['Attack subcategory'].dropna().unique(),
                default=None
            )
        
        # Filter data based on selections
        filtered_df = df.copy()
        if selected_category:
            filtered_df = filtered_df[filtered_df['Attack category'].isin(selected_category)]
        if selected_protocol:
            filtered_df = filtered_df[filtered_df['Protocol'].isin(selected_protocol)]
        if selected_subcategory:
            filtered_df = filtered_df[filtered_df['Attack subcategory'].isin(selected_subcategory)]
        
        # Show attack details
        if not filtered_df.empty:
            col1, col2 = st.columns(2)
            
            with col1:
                # Top Attack Names
                attack_counts = filtered_df['Attack Name'].value_counts().nlargest(10).reset_index()
                attack_counts.columns = ['Attack Name', 'Count']
                
                fig = px.bar(
                    attack_counts,
                    x='Count',
                    y='Attack Name',
                    orientation='h',
                    title='Top Attack Names',
                    color='Count',
                    color_continuous_scale='Reds'
                )
                fig.update_layout(yaxis={'categoryorder':'total ascending'})
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # CVE Distribution
                if 'CVE' in filtered_df.columns:
                    cve_counts = filtered_df['CVE'].dropna().value_counts().nlargest(10).reset_index()
                    if not cve_counts.empty:
                        cve_counts.columns = ['CVE', 'Count']
                        
                        fig = px.bar(
                            cve_counts,
                            x='CVE',
                            y='Count',
                            title='Top CVEs',
                            color='Count',
                            color_continuous_scale='Blues'
                        )
                        st.plotly_chart(fig, use_container_width=True)
                    else:
                        st.info("No CVE data available for the selected filters.")
            
            # Attack subcategory distribution
            subcategory_counts = filtered_df['Attack subcategory'].value_counts().reset_index()
            subcategory_counts.columns = ['Attack Subcategory', 'Count']
            
            fig = px.pie(
                subcategory_counts,
                values='Count',
                names='Attack Subcategory',
                title='Attack Subcategory Distribution',
                color_discrete_sequence=px.colors.qualitative.Pastel
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("No data available for the selected filters.")
    
    with tab3:
        st.markdown('<div class="sub-header">Network Traffic Analysis</div>', unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Source IP Analysis
            source_ip_counts = df['Source IP'].value_counts().nlargest(10).reset_index()
            source_ip_counts.columns = ['Source IP', 'Count']
            
            fig = px.bar(
                source_ip_counts,
                x='Source IP',
                y='Count',
                title='Top Source IPs',
                color='Count',
                color_continuous_scale='Viridis'
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Destination IP Analysis
            dest_ip_counts = df['Destination IP'].value_counts().nlargest(10).reset_index()
            dest_ip_counts.columns = ['Destination IP', 'Count']
            
            fig = px.bar(
                dest_ip_counts,
                x='Destination IP',
                y='Count',
                title='Top Destination IPs',
                color='Count',
                color_continuous_scale='Plasma'
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Port Analysis
        st.markdown('<div class="sub-header">Port Analysis</div>', unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Source Port Analysis
            source_port_counts = df['Source Port'].value_counts().nlargest(10).reset_index()
            source_port_counts.columns = ['Source Port', 'Count']
            
            fig = px.bar(
                source_port_counts,
                x='Source Port',
                y='Count',
                title='Top Source Ports',
                color='Count',
                color_continuous_scale='Teal'
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Destination Port Analysis
            dest_port_counts = df['Destination Port'].value_counts().nlargest(10).reset_index()
            dest_port_counts.columns = ['Destination Port', 'Count']
            
            fig = px.bar(
                dest_port_counts,
                x='Destination Port',
                y='Count',
                title='Top Destination Ports',
                color='Count',
                color_continuous_scale='Teal'
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Service Analysis based on destination ports
        if 'Service' in df.columns:
            service_counts = df['Service'].value_counts().nlargest(10).reset_index()
            service_counts.columns = ['Service', 'Count']
            
            fig = px.pie(
                service_counts,
                values='Count',
                names='Service',
                title='Services Targeted',
                color_discrete_sequence=px.colors.sequential.Plasma_r
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with tab4:
        st.markdown('<div class="sub-header">Data Explorer</div>', unsafe_allow_html=True)
        
        # Filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            search_term = st.text_input("Search in Attack Names", "")
        
        with col2:
            sort_by = st.selectbox(
                "Sort By",
                options=[col for col in df.columns if col in ["Time", "Attack category", "Protocol", "Source IP", "Destination IP"]],
                index=0 if "Time" in df.columns else 0
            )
        
        with col3:
            sort_order = st.radio("Order", ["Ascending", "Descending"], horizontal=True)
        
        # Apply filters
        explorer_df = df.copy()
        
        if search_term and 'Attack Name' in explorer_df.columns:
            explorer_df = explorer_df[explorer_df['Attack Name'].str.contains(search_term, case=False, na=False)]
        
        # Sort data
        if sort_by in explorer_df.columns:
            if sort_order == "Ascending":
                explorer_df = explorer_df.sort_values(by=sort_by)
            else:
                explorer_df = explorer_df.sort_values(by=sort_by, ascending=False)
        
        # Display data
        st.dataframe(
            explorer_df,
            use_container_width=True,
            column_config={
                "Time": st.column_config.DatetimeColumn("Time", format="YYYY-MM-DD HH:mm:ss") if "Time" in explorer_df.columns else None,
                "Attack Reference": st.column_config.LinkColumn("References") if "Attack Reference" in explorer_df.columns else None
            }
        )
        
        # Download button
        csv = explorer_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download Filtered Data as CSV",
            data=csv,
            file_name="filtered_cybersecurity_attacks.csv",
            mime="text/csv",
        )

# Main app logic
try:
    # Check if files are uploaded
    if attacks_file is not None:
        # Read the attacks CSV file
        attacks_df = pd.read_csv(attacks_file)
        
        # Read the ports CSV file if uploaded
        ports_df = None
        if ports_file is not None:
            ports_df = pd.read_csv(ports_file)
        
        # Process the data
        processed_df = process_data(attacks_df, ports_df)
        
        # Display the dashboard
        display_dashboard(processed_df)
    else:
        # Show sample data option if no file is uploaded
        st.markdown('<div class="sub-header">No Data Uploaded</div>', unsafe_allow_html=True)
        st.markdown("""
        To proceed and view the dashboard, kindly upload your cybersecurity attacks data.

        """)
        
        # Option to use sample data
        use_sample = st.checkbox("Use sample data for demonstration")
        
        if use_sample:
            # Create sample data
            sample_attacks = pd.DataFrame({
                'Attack category': ['Reconnaissance', 'Exploits', 'Exploits', 'DoS'],
                'Attack subcategory': ['HTTP', 'Unix Service', 'Browser', 'TCP Flood'],
                'Protocol': ['tcp', 'udp', 'tcp', 'tcp'],
                'Source IP': ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4'],
                'Source Port': [13284, 21223, 23357, 54321],
                'Destination IP': ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'],
                'Destination Port': [80, 22, 80, 443],
                'Attack Name': ['Web Server Scan', 'SSH Exploit', 'Browser Exploit', 'DDoS Attack'],
                'Attack Reference': ['CVE 2020-1234', 'CVE 2021-5678', 'CVE 2022-9012', 'CVE 2023-3456'],
                'Time': ['1624012800-1624012900', '1624013000-1624013100', '1624013200-1624013300', '1624013400-1624013500']
            })
            
            sample_ports = pd.DataFrame({
                'Port': [22, 80, 443],
                'Service': ['ssh', 'http', 'https'],
                'Description': ['SSH Remote Login', 'HTTP Web Server', 'HTTPS Secure Web Server']
            })
            
            # Process sample data
            processed_df = process_data(sample_attacks, sample_ports)
            
            # Display the dashboard with sample data
            st.warning("Using sample data for demonstration purposes. Upload your own files for actual analysis.")
            display_dashboard(processed_df)

except Exception as e:
    st.error(f"An error occurred: {e}")
    st.info("Please check that your CSV files are formatted correctly and try again.")