from html import escape
from ipwhois import IPWhois
from io import BytesIO
import re
import matplotlib.pyplot as plt
import base64

def verify_ip_address(ip_address):
    try:
        obj = IPWhois(ip_address)
        details = obj.lookup_rdap(depth=1)
        network = details.get("network", {})
        return {
            "IP": ip_address,
            "ASN": details.get("asn", "Unknown"),
            "ASN Country": details.get("asn_country_code", "Unknown"),
            "Network Name": network.get("name", "N/A"),
            "Network CIDR": network.get("cidr", "N/A"),
            "Network Range": network.get("range", "N/A"),
            "Network Description": network.get("description", "N/A")
        }
    except Exception as e:
        print(f"Error verifying IP: {str(e)}")
        return {"IP": ip_address, "Error": str(e)}

def generate_prediction_plot(spam_prob, ham_prob):
    """Generate a bar chart for spam/ham probabilities"""
    try:
        # Create figure and axis
        fig, ax = plt.subplots(figsize=(6, 4))
        
        # Data for bars
        categories = ['Ham', 'Spam']
        probabilities = [ham_prob, spam_prob]
        colors = ['green', 'red']
        
        # Create bars
        bars = ax.bar(categories, probabilities, color=colors, alpha=0.7)
        
        # Customize plot
        ax.set_ylim(0, 1)
        ax.set_title('Email Classification Probabilities', pad=20)
        ax.set_ylabel('Probability')
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, height,
                   f'{height:.2f}',
                   ha='center', va='bottom')
        
        # Convert plot to base64 string
        buf = BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format='png', dpi=300, bbox_inches='tight')
        plt.close()
        buf.seek(0)
        return base64.b64encode(buf.getvalue()).decode('utf-8')
        
    except Exception as e:
        print(f"Error generating plot: {str(e)}")
        return None

def generate_headers_section(headers, prediction_data=None):
    """Generate headers section with model prediction visualization"""
    html = """
        <div class="section-container">
            <h2 id="headers-section" class="section-title text-center">
                <i class="fa-solid fa-code"></i> Headers
            </h2>
    """
    
    
    # Add model prediction section first if available
    
    
    html += """
        <h3 id="headers-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-striped responsive-table">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
    """
    for key, value in headers["Data"].items():
        html += f"<tr><td>{str(key)}</td><td>{escape(str(value))}</td></tr>"
    html += """
            </tbody>
        </table>
    """
    # Perform IP lookup if 'x-received' exists
    if "x-received" in headers["Data"]:
        ip_matches = re.findall(r'\d+\.\d+\.\d+\.\d+', headers["Data"]["x-received"])
        if ip_matches:
            x_sender_ip = ip_matches[0]
            ip_info = verify_ip_address(x_sender_ip)
            headers["Investigation"]["X-Sender-Ip"] = ip_info

    html += """
        <h3 id="headers-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
    """
    # Copy the investigation dict so we can handle 'X-Sender-Ip' specially
    investigation_items = headers["Investigation"].copy()
    # If both exist, render X-Sender-Ip and Model Evaluation side-by-side
    if "X-Sender-Ip" in investigation_items and prediction_data:
        html += '<div class="row">'
        # X-Sender-Ip container
        html += """
            <div class="col-md-6">
                <div class="jumbotron">
                    <h3>X-Sender-Ip</h3>
                    <hr>
        """
        for k, v in investigation_items["X-Sender-Ip"].items():
            if isinstance(v, dict):
                html += f"<br><b>{k}:</b><br>"
                for sub_k, sub_v in v.items():
                    html += f"&nbsp;&nbsp;{sub_k}: {sub_v}<br>"
            else:
                html += f"<br><b>{k}:</b> {v}"
        html += """
                </div>
            </div>
        """
        # if True:
            # plot_img = generate_prediction_plot(prediction_data['spam_prob'], prediction_data['ham_prob'])
            # if plot_img:
            #     html += f"""
            #         <div class="row mb-4">
            #             <div class="col-12">
            #                 <div class="card">
            #                     <div class="card-header bg-primary text-white">
            #                         <h3 class="card-title mb-0">Spam Detection Results</h3>
            #                     </div>
            #                     <div class="card-body text-center">
            #                         <h4>Classification: <span class="badge badge-{prediction_data['prediction'].lower()}">{prediction_data['prediction']}</span></h4>
            #                         <img src="data:image/png;base64,{plot_img}" 
            #                             alt="Classification Results" 
            #                             style="max-width:100%; height:auto;">
            #                     </div>
            #                 </div>
            #             </div>
            #         </div>
            #     """
        # Model Evaluation container on the same row
        plot_img = generate_prediction_plot(prediction_data['spam_prob'], prediction_data['ham_prob'])
        if plot_img:
            html += f"""
                <div class="col-md-6">
                    <div class="jumbotron" style="text-align: center;">
                        <h3>Model Evaluation</h3>
                        <hr>
                        <p>Prediction: May be <strong>{prediction_data['prediction']}</strong>.</p>
                        <img src="data:image/png;base64,{plot_img}" alt="Model Evaluation Metrics" style="max-width:100%; height:auto;">
                    </div>
                </div>
            """
        html += "</div>"
        # Remove rendered key from further processing
        investigation_items.pop("X-Sender-Ip")
    else:
        # If no special handling is needed, render all investigation items normally
        plot_img = generate_prediction_plot(prediction_data['spam_prob'], prediction_data['ham_prob'])
        if plot_img:
            html += f"""
                <div class="col-md-6">
                    <div class="jumbotron" style="text-align: center;">
                        <h3>Model Evaluation</h3>
                        <hr>
                        <p>Prediction: May be <strong>{prediction_data['prediction']}</strong> email.</p>
                        <img src="data:image/png;base64,{plot_img}" alt="Model Evaluation Metrics" style="max-width:100%; height:auto;">
                    </div>
                </div>
            """
        html += "</div>"
    return html

def generate_links_section(links):
    html = """
        <div class="section-container">
            <h2 id="links-section" class="section-title text-center">
                <i class="fa-solid fa-link"></i> Links
            </h2>
    """
    html += """
        <h3 id="links-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered responsive-table">
            <thead class="thead-dark">
                <tr>
                    <th style="max-width:150px; white-space:nowrap;">Key</th>
                    <th style="max-width:300px; white-space:nowrap;">Value</th>
                </tr>
            </thead>
            <tbody>
    """
    for key, value in links["Data"].items():
        html += f"<tr><td>{key}</td><td style='max-width:300px; white-space:normal; word-break:break-word;'>{value}</td></tr>"
    html += """
            </tbody>
        </table>
    """
    html += """
        <h3 id="links-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <table class="table table-bordered responsive-table">
            <thead class="thead-dark">
                <tr>
                    <th style="max-width:150px; white-space:nowrap;">Key</th>
                    <th style="max-width:300px; white-space:nowrap;">Value</th>
                </tr>
            </thead>
            <tbody>
    """
    for index, values in links["Investigation"].items():
        html += f"<tr><td>{index}</td><td style='max-width:300px; white-space:normal; word-break:break-word;'>"
        for k, v in values.items():
            html += f"Verify: <a href='{v}' target='_blank'>{v}</a><br>"
        html += "</td></tr>"
    html += """
            </tbody>
        </table>
        <hr>
    """
    return html

def generate_attachment_section(attachments):
    """Generate HTML for attachments section including both Data and Investigation"""
    html = """
        <div class="section-container">
            <h2 id="attachments-section" class="section-title text-center">
                <i class="fa-solid fa-paperclip"></i> Attachments
            </h2>
    """
    
    # Data Section
    html += """
        <h3 id="attachments-data-section">
            <i class="fa-solid fa-chart-column"></i> Data
        </h3>
        <div class="card mb-4">
            <div class="card-body">
                <table class="table table-striped table-hover">
                    <thead class="thead-dark">
                        <tr>
                            <th>Filename</th>
                            <th>Content Type</th>
                            <th>SHA256</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    
    for filename, attachment in attachments["Data"].items():
        html += f"""
            <tr>
                <td>{attachment['Filename']}</td>
                <td>{attachment['Content Type']}</td>
                
                <td><code>{attachment['SHA256']}</code></td>
            </tr>
        """
    
    html += """
                    </tbody>
                </table>
            </div>
        </div>
    """
    
    # Investigation Section
    if attachments.get("Investigation"):
        html += """
            <h3 id="attachments-investigation-section">
                <i class="fa-solid fa-magnifying-glass"></i> Investigation
            </h3>
            <div class="card mb-4">
                <div class="card-body">
                    <div class="row">
        """
        
        for filename, investigation_data in attachments["Investigation"].items():
            html += f"""
                <div class="col-md-6 mb-3">
                    <div class="card">
                        <div class="card-header bg-info text-white">
                            Attachment Investigation
                        </div>
                        <div class="card-body">
                            <h5 class="card-title">{filename}</h5>
            """
            
            if "VirusTotal" in investigation_data:
                vt_data = investigation_data["VirusTotal"]
                html += """
                    <div class="list-group-item">
                        
                """
                for key, value in vt_data.items():
                    html += f"<p class='mb-1'><strong>{key}:</strong> {value}</p>"
                html += "</div>"
            
            html += """
                        </div>
                    </div>
                </div>
            """
        
        html += """
                    </div>
                </div>
            </div>
        """
    
    return html

def generate_table_from_json(json_obj):
    data = json_obj["Analysis"]
    info_data = json_obj["Information"]
    prediction_data = data.get("ModelPrediction")

    headers_cnt = len(data["Headers"]["Data"]) if data.get("Headers") else 0
    headers_inv_cnt = len(data["Headers"]["Investigation"]) if data.get("Headers") else 0
    links_cnt = len(data["Links"]["Data"]) if data.get("Links") else 0
    links_inv_cnt = len(data["Links"]["Investigation"]) if data.get("Links") else 0
    attach_cnt = len(data["Attachments"]["Data"]) if data.get("Attachments") else 0
    attach_inv_cnt = len(data["Attachments"]["Investigation"]) if data.get("Attachments") else 0

    html = f"""<!DOCTYPE html>
    <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.6.0/css/bootstrap.min.css">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <script async defer src="https://buttons.github.io/buttons.js"></script>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    background-color: #f8f9fa; 
                }}
                .navbar {{ 
                    background-color: #343a40; 
                }}
                .navbar-brand, .nav-link {{ 
                    color: #fff !important; 
                }}
                .container-fluid, .section-container {{ 
                    max-width: 1200px; 
                    margin: 20px auto; 
                    background-color: #fff; 
                    padding: 30px; 
                    border-radius: 8px; 
                    box-shadow: 0px 0px 15px rgba(0,0,0,0.1); 
                }}
                .info-section {{ 
                    background-color: #e9f7fe; 
                    padding: 30px; 
                    border-radius: 8px; 
                    margin-bottom: 30px; 
                }}
                .section-title {{
                    color: #2c3e50;
                    margin-bottom: 25px;
                    padding-bottom: 15px;
                    border-bottom: 2px solid #eaeaea;
                }}
                @media print {{ 
                    body {{ 
                        background-color: white !important;
                        padding: 20px !important;
                    }}
                    .navbar, .print-button {{ 
                        display: none !important; 
                    }}
                    .container-fluid, .section-container {{ 
                        margin: 15px !important;
                        padding: 20px !important;
                        border: 1px solid #dee2e6 !important;
                        box-shadow: none !important;
                        page-break-inside: avoid;
                    }}
                    .info-section {{
                        background-color: #ffffff !important;
                        border: 2px solid #e9f7fe !important;
                    }}
                    table {{
                        border: 1px solid #dee2e6 !important;
                    }}
                    td, th {{
                        padding: 8px !important;
                    }}
                }}
                .probability-bar {{
                    width: 100%;
                    background-color: #f0f0f0;
                    margin: 5px 0;
                    border-radius: 4px;
                }}
                .bar {{
                    height: 25px;
                    padding: 5px;
                    color: white;
                    border-radius: 4px;
                    display: flex;
                    align-items: center;
                    justify-content: flex-end;
                }}
                .spam-bar {{ background-color: #ff4444; }}
                .ham-bar {{ background-color: #44aa44; }}
                /* New Navigation Styles */
                .custom-navbar {{
                    background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                    padding: 1rem 0;
                    box-shadow: 0 2px 15px rgba(0,0,0,0.1);
                }}
                
                .nav-item {{
                    margin: 0 10px;
                    position: relative;
                }}
                
                .nav-link {{
                    color: #fff !important;
                    font-weight: 500;
                    padding: 0.5rem 1rem;
                    border-radius: 5px;
                    transition: all 0.3s ease;
                }}
                
                .nav-link:hover {{
                    background: rgba(255,255,255,0.1);
                    transform: translateY(-2px);
                }}
                
                .nav-link.active {{
                    background: rgba(255,255,255,0.2);
                    color: #fff !important;
                }}
                
                .navbar-brand {{
                    font-size: 1.5rem;
                    font-weight: bold;
                    color: #fff !important;
                    text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
                }}
                
                .nav-badge {{
                    position: absolute;
                    top: -5px;
                    right: -5px;
                    padding: 3px 6px;
                    border-radius: 50%;
                    font-size: 0.7rem;
                    background: #ff4444;
                }}
                
                @media (max-width: 768px) {{
                    .navbar-nav {{
                        background: rgba(0,0,0,0.1);
                        padding: 10px;
                        border-radius: 8px;
                    }}
                }}
            </style>
        </head>
        <body>
            <!-- Enhanced Navigation Bar -->
            <nav class="navbar navbar-expand-lg custom-navbar sticky-top">
                <div class="container">
                    <a class="navbar-brand" href="#">
                        <i class="fas fa-shield-alt"></i> Email Analyzer
                    </a>
                    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"
                            aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                        <span class="navbar-toggler-icon"></span>
                    </button>
                    <div class="collapse navbar-collapse" id="navbarNav">
                        <ul class="navbar-nav ml-auto">
                            <li class="nav-item">
                                <a class="nav-link active" href="#info-section">
                                    <i class="fas fa-info-circle"></i> Info
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="#headers-section">
                                    <i class="fas fa-code"></i> Headers
                                    {f'<span class="nav-badge">{headers_cnt}</span>' if headers_cnt else ''}
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="#links-section">
                                    <i class="fas fa-link"></i> Links
                                    {f'<span class="nav-badge">{links_cnt}</span>' if links_cnt else ''}
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="#attachments-section">
                                    <i class="fas fa-paperclip"></i> Attachments
                                    {f'<span class="nav-badge">{attach_cnt}</span>' if attach_cnt else ''}
                                </a>
                            </li>
                            <li class="nav-item">
                                <button class="btn btn-light btn-sm ml-2" onclick="window.print()">
                                    <i class="fas fa-print"></i> Print
                                </button>
                            </li>
                        </ul>
                    </div>
                </div>
            </nav>
            
            <!-- Main Content Container -->
            <div class="container-fluid">
                <h1 class="text-center my-4">Email Analysis Report</h1>
                
                <div class="info-section" id="info-section">
                    <h2 class="text-center"><i class="fa-solid fa-circle-info"></i> Information</h2>
                    <hr>
                    <div class="row">
                        <div class="col-md-6">
                            <h3 class="text-center">Project Details</h3>
                            <table class="table">
                                <tr>
                                    <td>Name</td>
                                    <td>{info_data["Project"]["Name"]}</td>
                                </tr>
                                <tr>
                                    <td>URL</td>
                                    <td><a href="{info_data["Project"]["Url"]}">{info_data["Project"]["Url"]}</a></td>
                                </tr>
                            </table>
                        </div>
                        <div class="col-md-6">
                            <h3 class="text-center">Scan Details</h3>
                            <table class="table">
                                <tr>
                                    <td>Filename</td>
                                    <td>{info_data["Scan"]["Filename"]}</td>
                                </tr>
                                <tr>
                                    <td>Generated</td>
                                    <td>{info_data["Scan"]["Generated"]}</td>
                                </tr>
                            </table>
                        </div>
                    </div>
                </div>
            """

    # Add sections
    if data.get("Headers"):
        html += generate_headers_section(data["Headers"], prediction_data)
    if data.get("Links"):
        html += generate_links_section(data["Links"])
    if data.get("Attachments"):
        html += generate_attachment_section(data["Attachments"])

    # Close HTML
    html += """
            </div>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.6.0/js/bootstrap.min.js"></script>
        </body>
    </html>
    """
    
    return html

