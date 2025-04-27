import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import numpy as np
import io
import re

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
    .mapping-section {
        padding: 1.5rem;
        border-radius: 0.5rem;
        background-color: #F0FDF4;
        margin-bottom: 1.5rem;
        border: 1px dashed #10B981;
    }
    .stAlert {
        margin-top: 1rem;
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

# Define expected columns and their potential aliases
EXPECTED_COLUMNS = {
    "attack_category": ["Attack category", "attack_category", "attack type", "category", "Category"],
    "attack_subcategory": ["Attack subcategory", "attack_subcategory", "subcategory", "sub_category", "Subcategory"],
    "protocol": ["Protocol", "protocol", "proto", "Protocol Type"],
    "source_ip": ["Source IP", "source_ip", "src_ip", "src ip", "Source"],
    "source_port": ["Source Port", "source_port", "src_port", "src port"],
    "destination_ip": ["Destination IP", "destination_ip", "dst_ip", "dst ip", "Target", "target_ip", "Destination"],
    "destination_port": ["Destination Port", "destination_port", "dst_port", "dst port", "target_port"],
    "attack_name": ["Attack Name", "attack_name", "name", "signature", "Signature Name"],
    "attack_reference": ["Attack Reference", "attack_reference", "reference", "cve", "CVE"],
    "time": ["Time", "time", "timestamp", "date", "Date", "datetime", "event_time"],
}

# Function to automatically map columns in the dataframe
def auto_map_columns(df):
    column_mapping = {}
    
    # Try to map each expected column to an actual column in the dataframe
    for expected_col, possible_names in EXPECTED_COLUMNS.items():
        for col_name in possible_names:
            if col_name in df.columns:
                column_mapping[expected_col] = col_name
                break
            
    return column_mapping

# Function to extract CVE from text
def extract_cve(text):
    if pd.isna(text):
        return None
    
    # Try to find CVE pattern (CVE-YYYY-NNNNN or CVE YYYY-NNNNN)
    cve_pattern = r'CVE[-\s](\d{4}-\d+)'
    match = re.search(cve_pattern, text, re.IGNORECASE)
    
    if match:
        return f"CVE-{match.group(1)}"
    return None

# Function to parse and convert timestamp
def parse_timestamp(time_str):
    if pd.isna(time_str):
        return pd.NaT
        
    # Handle UNIX timestamp with range format (1421927414-1421927416)
    if isinstance(time_str, str) and '-' in time_str:
        try:
            start_time = time_str.split('-')[0].strip()
            return pd.to_datetime(float(start_time), unit='s')
        except:
            pass
            
    # Try standard parsing
    try:
        return pd.to_datetime(time_str)
    except:
        return pd.NaT

# Function to load and clean data
def process_data(attacks_df, ports_df=None, column_mapping=None):
    if column_mapping is None:
        column_mapping = auto_map_columns(attacks_df)
    
    # Create a standardized dataframe with consistent column names
    std_df = pd.DataFrame()
    
    # Map and standardize columns
    for std_col, orig_col in column_mapping.items():
        if orig_col in attacks_df.columns:
            std_df[std_col] = attacks_df[orig_col]
    
    # Drop rows with missing essential data - modified to check if columns exist first
    essential_cols = ['attack_category', 'source_ip', 'destination_ip']
    existing_essential_cols = [col for col in essential_cols if col in std_df.columns]
    
    if existing_essential_cols:
        std_df = std_df.dropna(subset=existing_essential_cols)
    
    # Convert timestamp to datetime if time column exists
    if 'time' in std_df.columns:
        std_df['time'] = std_df['time'].apply(parse_timestamp)
    
    # Extract CVE from Attack Reference if column exists
    if 'attack_reference' in std_df.columns:
        std_df['cve'] = std_df['attack_reference'].apply(extract_cve)
    
    # Add service name based on destination port if ports_df is available and destination_port exists
    if ports_df is not None and 'destination_port' in std_df.columns:
        # Try to find the port column in ports_df
        port_col = None
        service_col = None
        
        for col in ports_df.columns:
            if col.lower() in ['port', 'portnumber', 'port_number', 'port number']:
                port_col = col
            elif col.lower() in ['service', 'servicename', 'service_name', 'service name']:
                service_col = col
        
        if port_col and service_col:
            # Convert ports to numeric to ensure proper mapping
            ports_df[port_col] = pd.to_numeric(ports_df[port_col], errors='coerce')
            std_df['destination_port'] = pd.to_numeric(std_df['destination_port'], errors='coerce')
            
            # Create ports dictionary and map services
            ports_dict = dict(zip(ports_df[port_col], ports_df[service_col]))
            std_df['service'] = std_df['destination_port'].map(lambda x: ports_dict.get(x, "Unknown"))
    
    return std_df

# Function to display column mapping interface
def display_column_mapping(df):
    st.markdown('<div class="mapping-section">', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Column Mapping</div>', unsafe_allow_html=True)
    st.write("Map your CSV columns to standard fields. This helps the dashboard understand your data.")
    
    column_mapping = {}
    
    # Create a dropdown for each expected column
    cols = st.columns(4)
    
    for i, (expected_col, possible_names) in enumerate(EXPECTED_COLUMNS.items()):
        col_index = i % 4
        with cols[col_index]:
            column_options = ["None"] + list(df.columns)
            
            # Try to find a default selection
            default_idx = 0
            for j, col_name in enumerate(column_options[1:], 1):
                if col_name in possible_names:
                    default_idx = j
                    break
            
            selected = st.selectbox(
                f"{expected_col.replace('_', ' ').title()}", 
                column_options,
                index=default_idx,
                key=f"map_{expected_col}"
            )
            
            if selected != "None":
                column_mapping[expected_col] = selected
    
    st.markdown('</div>', unsafe_allow_html=True)
    return column_mapping

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
            
        # Only display metrics for columns that exist
        with col2:
            if 'attack_category' in df.columns:
                st.markdown('<div class="card">', unsafe_allow_html=True)
                st.metric("Unique Attack Categories", f"{df['attack_category'].nunique()}")
                st.markdown('</div>', unsafe_allow_html=True)
            
        with col3:
            if 'source_ip' in df.columns:
                st.markdown('<div class="card">', unsafe_allow_html=True)
                st.metric("Unique Source IPs", f"{df['source_ip'].nunique()}")
                st.markdown('</div>', unsafe_allow_html=True)
            
        with col4:
            if 'destination_ip' in df.columns:
                st.markdown('<div class="card">', unsafe_allow_html=True)
                st.metric("Unique Target IPs", f"{df['destination_ip'].nunique()}")
                st.markdown('</div>', unsafe_allow_html=True)
        
        # Attack distribution by category - only if column exists
        if 'attack_category' in df.columns:
            st.markdown('<div class="sub-header">Attack Distribution</div>', unsafe_allow_html=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                category_counts = df['attack_category'].value_counts().reset_index()
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
                if 'protocol' in df.columns:
                    protocol_counts = df['protocol'].value_counts().reset_index()
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
        
        # Timeline of attacks - only if time column exists and has valid data
        if 'time' in df.columns and not df['time'].isna().all():
            st.markdown('<div class="sub-header">Attack Timeline</div>', unsafe_allow_html=True)
            
            # Group by day and count attacks
            df_time = df.copy()
            df_time['date'] = df_time['time'].dt.date
            timeline = df_time.groupby('date').size().reset_index(name='Count')
            
            fig = px.line(
                timeline, 
                x='date', 
                y='Count',
                title='Number of Attacks Over Time',
                markers=True
            )
            fig.update_layout(xaxis_title="Date", yaxis_title="Number of Attacks")
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        st.markdown('<div class="sub-header">Attack Analysis</div>', unsafe_allow_html=True)
        
        # Only show filters for columns that exist
        filter_cols = st.columns(3)
        
        filter_data = {}
        
        with filter_cols[0]:
            if 'attack_category' in df.columns:
                filter_data['category'] = st.multiselect(
                    "Select Attack Category",
                    options=df['attack_category'].dropna().unique(),
                    default=df['attack_category'].dropna().unique()[0] if not df['attack_category'].dropna().empty else None
                )
        
        with filter_cols[1]:
            if 'protocol' in df.columns:
                filter_data['protocol'] = st.multiselect(
                    "Select Protocol",
                    options=df['protocol'].dropna().unique(),
                    default=None
                )
            
        with filter_cols[2]:
            if 'attack_subcategory' in df.columns:
                filter_data['subcategory'] = st.multiselect(
                    "Select Attack Subcategory",
                    options=df['attack_subcategory'].dropna().unique(),
                    default=None
                )
        
        # Filter data based on selections
        filtered_df = df.copy()
        if 'category' in filter_data and filter_data['category'] and 'attack_category' in filtered_df.columns:
            filtered_df = filtered_df[filtered_df['attack_category'].isin(filter_data['category'])]
        if 'protocol' in filter_data and filter_data['protocol'] and 'protocol' in filtered_df.columns:
            filtered_df = filtered_df[filtered_df['protocol'].isin(filter_data['protocol'])]
        if 'subcategory' in filter_data and filter_data['subcategory'] and 'attack_subcategory' in filtered_df.columns:
            filtered_df = filtered_df[filtered_df['attack_subcategory'].isin(filter_data['subcategory'])]
        
        # Show attack details only if data exists after filtering
        if not filtered_df.empty:
            col1, col2 = st.columns(2)
            
            # Only display charts for columns that exist
            attack_name_displayed = False
            with col1:
                if 'attack_name' in filtered_df.columns:
                    attack_name_displayed = True
                    attack_counts = filtered_df['attack_name'].value_counts().nlargest(10).reset_index()
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
                if 'cve' in filtered_df.columns:
                    cve_counts = filtered_df['cve'].dropna().value_counts().nlargest(10).reset_index()
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
                elif not attack_name_displayed:
                    st.write("No attack name or CVE data available in the dataset.")
            
            # Attack subcategory distribution - only if column exists
            if 'attack_subcategory' in filtered_df.columns:
                subcategory_counts = filtered_df['attack_subcategory'].value_counts().reset_index()
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
        
        # Only show IP analysis if columns exist
        ip_analysis_displayed = False
        if 'source_ip' in df.columns or 'destination_ip' in df.columns:
            col1, col2 = st.columns(2)
            
            with col1:
                if 'source_ip' in df.columns:
                    ip_analysis_displayed = True
                    source_ip_counts = df['source_ip'].value_counts().nlargest(10).reset_index()
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
                if 'destination_ip' in df.columns:
                    ip_analysis_displayed = True
                    dest_ip_counts = df['destination_ip'].value_counts().nlargest(10).reset_index()
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
        
        if not ip_analysis_displayed:
            st.write("No IP information available in the dataset.")
        
        # Only show port analysis if columns exist
        port_analysis_displayed = False
        if 'source_port' in df.columns or 'destination_port' in df.columns:
            st.markdown('<div class="sub-header">Port Analysis</div>', unsafe_allow_html=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                if 'source_port' in df.columns:
                    port_analysis_displayed = True
                    source_port_counts = df['source_port'].value_counts().nlargest(10).reset_index()
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
                if 'destination_port' in df.columns:
                    port_analysis_displayed = True
                    dest_port_counts = df['destination_port'].value_counts().nlargest(10).reset_index()
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
        
        # Only show service analysis if column exists
        if 'service' in df.columns:
            service_counts = df['service'].value_counts().nlargest(10).reset_index()
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
            search_col = st.selectbox(
                "Search in Column",
                options=["None"] + list(df.columns),
                index=0
            )
            
            if search_col != "None":
                search_term = st.text_input(f"Search in {search_col}", "")
            else:
                search_term = ""
        
        with col2:
            sort_columns = [col for col in df.columns]
            if sort_columns:
                sort_by = st.selectbox(
                    "Sort By",
                    options=sort_columns,
                    index=0 if sort_columns else 0
                )
            else:
                sort_by = None
        
        with col3:
            sort_order = st.radio("Order", ["Ascending", "Descending"], horizontal=True)
        
        # Apply filters
        explorer_df = df.copy()
        
        if search_term and search_col != "None" and search_col in explorer_df.columns:
            if pd.api.types.is_string_dtype(explorer_df[search_col]):
                explorer_df = explorer_df[explorer_df[search_col].str.contains(search_term, case=False, na=False)]
            else:
                try:
                    # Try to convert search term to the column data type
                    search_value = type(explorer_df[search_col].iloc[0])(search_term)
                    explorer_df = explorer_df[explorer_df[search_col] == search_value]
                except:
                    st.warning(f"Cannot search in column {search_col} with value '{search_term}'")
        
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
            height=400
        )
        
        # Download button
        csv = explorer_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download Filtered Data as CSV",
            data=csv,
            file_name="filtered_cybersecurity_attacks.csv",
            mime="text/csv",
        )

# Function to detect file encoding
def detect_encoding(file):
    """Try to detect the file encoding."""
    encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
    
    for encoding in encodings:
        try:
            # Save current position
            pos = file.tell()
            # Try to read with the encoding
            file.seek(0)
            pd.read_csv(file, encoding=encoding, nrows=5)
            # Reset position
            file.seek(pos)
            return encoding
        except:
            # Reset position for next try
            file.seek(pos)
            continue
    
    # Default to utf-8 if no encoding works
    file.seek(0)
    return 'utf-8'

# Main app logic
try:
    # Check if files are uploaded
    if attacks_file is not None:
        # Read the attacks CSV file
        encoding = detect_encoding(attacks_file)
        attacks_df = pd.read_csv(attacks_file, encoding=encoding)
        
        # Show column mapping interface if not auto-detecting
        st.markdown("### Configure Data Mapping")
        
        auto_detect = st.checkbox("Auto-detect columns", value=True)
        
        if auto_detect:
            column_mapping = auto_map_columns(attacks_df)
            
            # Display the auto-detected mapping
            st.markdown("#### Auto-detected Column Mapping")
            mapping_df = pd.DataFrame([
                {"Standard Field": k, "CSV Column": v} 
                for k, v in column_mapping.items()
            ])
            st.dataframe(mapping_df, use_container_width=True)
            
            # Allow manual override if needed
            if st.checkbox("Override auto-detection"):
                column_mapping = display_column_mapping(attacks_df)
        else:
            column_mapping = display_column_mapping(attacks_df)
        
        # Read the ports CSV file if uploaded
        ports_df = None
        if ports_file is not None:
            ports_encoding = detect_encoding(ports_file)
            ports_df = pd.read_csv(ports_file, encoding=ports_encoding)
        
        # Process the data
        processed_df = process_data(attacks_df, ports_df, column_mapping)
        
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
            
            # Process sample data with auto-mapping
            column_mapping = auto_map_columns(sample_attacks)
            processed_df = process_data(sample_attacks, sample_ports, column_mapping)
            
            # Display the dashboard with sample data
            st.warning("Using sample data for demonstration purposes. Upload your own files for actual analysis.")
            display_dashboard(processed_df)

except Exception as e:
    st.error(f"An error occurred: {str(e)}")
    st.info("Please check that your CSV files are formatted correctly and try again.")