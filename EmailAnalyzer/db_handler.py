import sqlite3
import os
from datetime import datetime

class DatabaseHandler:
    def __init__(self):
        self.db_path = os.path.join(os.path.dirname(__file__), "database", "email_analysis.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_database()

    def init_database(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Enhanced emails table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT,
                    subject TEXT,
                    from_address TEXT,
                    to_address TEXT,
                    reply_to TEXT,
                    date_received DATETIME,
                    date_analyzed DATETIME,
                    spam_probability REAL,
                    ham_probability REAL,
                    spam_status TEXT,
                    confidence_level TEXT,
                    spoof_check_result TEXT,
                    sender_ip TEXT,
                    sender_asn TEXT,
                    sender_country TEXT,
                    total_attachments INTEGER,
                    total_links INTEGER,
                    analysis_duration REAL
                )
            ''')

            # Enhanced attachments table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attachments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_id INTEGER,
                    filename TEXT,
                    content_type TEXT,
                    sha256 TEXT,
                    size INTEGER,
                    vt_status TEXT,
                    vt_detection_ratio TEXT,
                    vt_analysis_date DATETIME,
                    vt_last_analysis_stats TEXT,
                    vt_type_description TEXT,
                    harmless_count INTEGER,
                    malicious_count INTEGER,
                    stored_path TEXT,
                    analysis_duration REAL,
                    FOREIGN KEY (email_id) REFERENCES emails (id)
                )
            ''')

            # Enhanced links table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_id INTEGER,
                    url TEXT,
                    vt_result TEXT,
                    analysis_date DATETIME,
                    is_malicious BOOLEAN,
                    FOREIGN KEY (email_id) REFERENCES emails (id)
                )
            ''')

            conn.commit()

    def store_analysis(self, analysis_data):
        """Store email analysis results in database"""
        try:
            start_time = datetime.now()
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                headers = analysis_data["Analysis"]["Headers"]["Data"]
                model_pred = analysis_data["Analysis"]["ModelPrediction"]
                investigation = analysis_data["Analysis"]["Headers"]["Investigation"]
                
                # Get sender IP info if available
                sender_ip_info = investigation.get("X-Sender-Ip", {})
                spoof_check = investigation.get("Spoof Check", {})

                cursor.execute('''
                    INSERT INTO emails (
                        filename, subject, from_address, to_address, reply_to,
                        date_received, date_analyzed, spam_probability, 
                        ham_probability, spam_status, confidence_level,
                        spoof_check_result, sender_ip, sender_asn,
                        sender_country, total_attachments, total_links,
                        analysis_duration
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    analysis_data["Information"]["Scan"]["Filename"],
                    headers.get("subject", "N/A"),
                    headers.get("from", "N/A"),
                    headers.get("to", "N/A"),
                    headers.get("reply-to", "N/A"),
                    headers.get("date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    model_pred.get("spam_prob", 0.0),
                    model_pred.get("ham_prob", 0.0),
                    model_pred.get("prediction", "Unknown"),
                    model_pred.get("confidence_level", "Unknown"),
                    spoof_check.get("Conclusion", "N/A"),
                    sender_ip_info.get("IP", "N/A"),
                    sender_ip_info.get("ASN", "N/A"),
                    sender_ip_info.get("ASN Country", "N/A"),
                    len(analysis_data["Analysis"].get("Attachments", {}).get("Data", {})),
                    len(analysis_data["Analysis"].get("Links", {}).get("Data", {})),
                    (datetime.now() - start_time).total_seconds()
                ))
                
                email_id = cursor.lastrowid

                # Store attachments with enhanced data
                if "Attachments" in analysis_data["Analysis"]:
                    for filename, attach_data in analysis_data["Analysis"]["Attachments"]["Data"].items():
                        vt_data = analysis_data["Analysis"]["Attachments"]["Investigation"].get(filename, {}).get("VirusTotal", {})
                        
                        cursor.execute('''
                            INSERT INTO attachments (
                                email_id, filename, content_type, sha256, 
                                size, vt_status, vt_detection_ratio,
                                vt_analysis_date, vt_type_description,
                                harmless_count, malicious_count,
                                stored_path, analysis_duration
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            email_id,
                            attach_data["Filename"],
                            attach_data["Content Type"],
                            attach_data["SHA256"],
                            attach_data["Size"],
                            vt_data.get("status", "Unknown"),
                            vt_data.get("detection_ratio", "N/A"),
                            vt_data.get("last_analyzed", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                            vt_data.get("type", "Unknown"),
                            vt_data.get("harmless count", 0),
                            vt_data.get("malicious count", 0),
                            attach_data.get("Stored Path", "N/A"),
                            vt_data.get("analysis_duration", 0.0)
                        ))

                # Store links with timestamps
                if "Links" in analysis_data["Analysis"]:
                    for link_id, link_url in analysis_data["Analysis"]["Links"]["Data"].items():
                        cursor.execute('''
                            INSERT INTO links (
                                email_id, url, vt_result, analysis_date, is_malicious
                            ) VALUES (?, ?, ?, ?, ?)
                        ''', (
                            email_id,
                            link_url,
                            "Analysis Complete",
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            False
                        ))

                conn.commit()
                return email_id

        except Exception as e:
            print(f"Database error: {str(e)}")
            return None

    def get_analysis_history(self, limit=10):
        """Retrieve recent analysis history"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT emails.*, 
                       COUNT(DISTINCT attachments.id) as attachment_count,
                       COUNT(DISTINCT links.id) as link_count
                FROM emails
                LEFT JOIN attachments ON emails.id = attachments.email_id
                LEFT JOIN links ON emails.id = links.email_id
                GROUP BY emails.id
                ORDER BY emails.date_analyzed DESC
                LIMIT ?
            ''', (limit,))
            return cursor.fetchall()
