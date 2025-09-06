import requests
import time
from datetime import datetime
from config import VIRUSTOTAL_API_KEYS, MAX_RETRIES, ANALYSIS_WAIT_TIME

class VirusTotalService:
    def __init__(self):
        self.api_keys = VIRUSTOTAL_API_KEYS
        self.current_key = 0
        self.base_url = "https://www.virustotal.com/api/v3"

    def _get_next_key(self):
        self.current_key = (self.current_key + 1) % len(self.api_keys)
        return self.api_keys[self.current_key]

    def get_file_analysis(self, file_hash):
        """Check if file exists in VT"""
        headers = {
            "accept": "application/json",
            "x-apikey": self._get_next_key()
        }
        response = requests.get(f"{self.base_url}/files/{file_hash}", headers=headers)
        return response.json() if response.status_code == 200 else None

    def upload_file(self, file_path, file_name):
        """Upload file to VT"""
        headers = {
            "accept": "application/json",
            "x-apikey": self._get_next_key()
        }
        with open(file_path, 'rb') as f:
            files = {"file": (file_name, f)}
            response = requests.post(f"{self.base_url}/files", headers=headers, files=files)
            return response.json() if response.status_code == 200 else None

    def get_analysis_results(self, file_hash, max_retries=30):
        """Get analysis results with extended retries"""
        print(f"Getting analysis results for {file_hash}")
        for attempt in range(max_retries):
            headers = {
                "accept": "application/json",
                "x-apikey": self._get_next_key()
            }
            try:
                # First try to get file info directly
                response = requests.get(f"{self.base_url}/files/{file_hash}", headers=headers)
                if response.status_code == 200:
                    return response.json()

                # If not found, check analysis status
                response = requests.get(f"{self.base_url}/analyses/{file_hash}", headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    status = data["data"]["attributes"]["status"]
                    
                    if status == "completed":
                        return self.get_file_analysis(file_hash)
                    else:
                        print(f"Analysis in progress (attempt {attempt + 1}/{max_retries})")
                        time.sleep(2)
                else:
                    print(f"API error: {response.status_code}")
                    time.sleep(2)
            except Exception as e:
                print(f"Error in attempt {attempt + 1}: {str(e)}")
                time.sleep(2)
        return None

    def process_file(self, file_path, file_name, file_hash):
        """Complete file processing workflow"""
        print(f"\nProcessing {file_name} with VirusTotal...")
        
        # First check if file exists
        existing_analysis = self.get_file_analysis(file_hash)
        if existing_analysis:
            print(f"Found existing analysis for {file_name}")
            return self._format_results(existing_analysis, "existing")

        # If not found, upload file
        print(f"No existing analysis found. Uploading {file_name}...")
        upload_result = self.upload_file(file_path, file_name)
        if not upload_result:
            return {
                "status": "error",
                "message": "Failed to upload file",
                "links": {
                    "VirusTotal Search": f"https://www.virustotal.com/gui/search/{file_hash}"
                }
            }

        print("Upload successful. Waiting for analysis completion...")
        # Wait for analysis to complete
        analysis_result = self.get_analysis_results(file_hash)
        if analysis_result:
            print("Analysis completed successfully")
            return self._format_results(analysis_result, "new")
        
        # Only reach here if analysis failed after all retries
        return {
            "status": "error",
            "message": "Analysis timed out",
            "links": {
                "VirusTotal File": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        }

    def _format_results(self, analysis_data, analysis_type="existing"):
        """Format analysis results for display"""
        try:
            attributes = analysis_data["data"]["attributes"]
            file_hash = analysis_data["data"]["id"]
            
            result = {
                "status": "completed",
                "analysis_type": analysis_type,
                "size": attributes.get("size", "N/A"),
                "type": attributes.get("type_description", "N/A"),
                "harmless count": attributes["total_votes"]["harmless"],
                "malicious count": attributes["total_votes"]["malicious"],
            }

            # Add detection stats if available
            stats = attributes.get("last_analysis_stats", {})
            if stats:
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                result["detection_ratio"] = f"{malicious}/{total}"
                result["detection_status"] = "Clean" if malicious == 0 else "Suspicious" if malicious < 3 else "Malicious"

            # Add reputation if available
            

            # Add links
            # result["links"] = {
            #     "VirusTotal File": f"https://www.virustotal.com/gui/file/{file_hash}",
            #     }

            return result
        except Exception as e:
            return {"error": str(e)}
