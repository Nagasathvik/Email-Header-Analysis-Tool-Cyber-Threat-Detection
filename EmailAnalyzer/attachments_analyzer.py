import requests
from datetime import datetime
from email import message_from_file, policy
import json
import hashlib
import os
from virustotal_service import VirusTotalService

def get_virustotal_info(hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        attributes = data["data"]["attributes"]
        return {
            "Size": attributes.get("size", "N/A"),
            "Type": attributes.get("type_description", "N/A"),
            "Last Analysis": datetime.utcfromtimestamp(attributes.get("last_analysis_date", 0)).strftime('%Y-%m-%d %H:%M:%S'),
            "Harmless Votes": attributes.get("total_votes", {}).get("harmless", 0),
            "Malicious Votes": attributes.get("total_votes", {}).get("malicious", 0)
        }
    except Exception as e:
        return {"Error": str(e)}

def get_attachments(filename: str, investigation):
    # Initialize VirusTotal service with multiple API keys
    vt_service = VirusTotalService([
        'api_key1',  # Replace with actual keys
        'api_key2',
        'api_key3',
    ])

    with open(filename, "r") as f:
        msg = message_from_file(f, policy=policy.default)
    
    data = {"Attachments": {"Data": {}, "Investigation": {}}}

    for attachment in msg.iter_attachments():
        file_content = attachment.get_payload(decode=True)
        filename = attachment.get_filename()
        
        if not filename or not file_content:
            continue

        sha256 = hashlib.sha256(file_content).hexdigest()
        
        # Save attachment temporarily
        temp_path = f"temp_{filename}"
        with open(temp_path, 'wb') as f:
            f.write(file_content)

        attached_file = {
            "Filename": filename,
            "Content Type": attachment.get_content_type(),
            "Size": len(file_content),
            "SHA256": sha256
        }

        # Add to Data section
        data["Attachments"]["Data"][filename] = attached_file

        # If investigation requested, process with VirusTotal
        if investigation:
            vt_results = vt_service.process_file(temp_path, filename, sha256)
            data["Attachments"]["Investigation"][filename] = {
                "VirusTotal": vt_results,
                "Links": {
                    "VirusTotal File": f'https://www.virustotal.com/gui/file/{sha256}',
                    "VirusTotal Graph": f'https://www.virustotal.com/gui/graph/{sha256}'
                }
            }

        # Cleanup temp file
        try:
            os.remove(temp_path)
        except:
            pass

    return data
