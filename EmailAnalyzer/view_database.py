import sqlite3
from tabulate import tabulate
import os

class DatabaseViewer:
    def __init__(self):
        self.db_path = os.path.join(os.path.dirname(__file__), "database", "email_analysis.db")
        if not os.path.exists(self.db_path):
            raise FileNotFoundError("Database file not found!")

    def view_recent_emails(self, limit=5):
        """View most recent email analyses"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, filename, subject, from_address, date_analyzed, 
                       spam_status, confidence_level, total_attachments, total_links 
                FROM emails 
                ORDER BY date_analyzed DESC 
                LIMIT ?
            ''', (limit,))
            rows = cursor.fetchall()
            headers = ['ID', 'Filename', 'Subject', 'From', 'Analyzed', 'Status', 
                      'Confidence', 'Attachments', 'Links']
            print("\nRecent Email Analyses:")
            print(tabulate(rows, headers=headers, tablefmt='grid'))

    def view_email_details(self, email_id):
        """View detailed information about a specific email"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get email details
            cursor.execute('''
                SELECT * FROM emails WHERE id = ?
            ''', (email_id,))
            email = cursor.fetchone()
            if not email:
                print(f"No email found with ID {email_id}")
                return

            # Get attachments
            cursor.execute('''
                SELECT filename, content_type, vt_status, vt_detection_ratio 
                FROM attachments 
                WHERE email_id = ?
            ''', (email_id,))
            attachments = cursor.fetchall()

            # Get links
            cursor.execute('''
                SELECT url, vt_result, analysis_date 
                FROM links 
                WHERE email_id = ?
            ''', (email_id,))
            links = cursor.fetchall()

            # Print formatted results
            print("\nEmail Details:")
            print("=" * 80)
            print(f"Subject: {email[2]}")
            print(f"From: {email[3]} -> To: {email[4]}")
            print(f"Analysis Date: {email[7]}")
            print(f"Spam Status: {email[10]} (Confidence: {email[11]})")
            print(f"Spam Probability: {email[8]:.2f}")
            
            if attachments:
                print("\nAttachments:")
                print(tabulate(attachments, 
                             headers=['Filename', 'Type', 'VT Status', 'Detection'],
                             tablefmt='grid'))
            
            if links:
                print("\nLinks:")
                print(tabulate(links, 
                             headers=['URL', 'VT Result', 'Analyzed'],
                             tablefmt='grid'))

    def view_statistics(self):
        """View overall statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            stats = {}
            
            # Total emails analyzed
            cursor.execute('SELECT COUNT(*) FROM emails')
            stats['Total Emails'] = cursor.fetchone()[0]
            
            # Spam vs Ham ratio
            cursor.execute('''
                SELECT spam_status, COUNT(*) 
                FROM emails 
                GROUP BY spam_status
            ''')
            stats['Classification'] = dict(cursor.fetchall())
            
            # Total attachments
            cursor.execute('SELECT COUNT(*) FROM attachments')
            stats['Total Attachments'] = cursor.fetchone()[0]
            
            # Total links
            cursor.execute('SELECT COUNT(*) FROM links')
            stats['Total Links'] = cursor.fetchone()[0]

            print("\nDatabase Statistics:")
            print("=" * 40)
            for key, value in stats.items():
                print(f"{key}: {value}")

if __name__ == "__main__":
    try:
        viewer = DatabaseViewer()
        
        while True:
            print("\nEmail Analysis Database Viewer")
            print("1. View Recent Emails")
            print("2. View Email Details")
            print("3. View Statistics")
            print("4. Exit")
            
            choice = input("\nEnter your choice (1-4): ")
            
            if choice == '1':
                limit = int(input("How many records to show? "))
                viewer.view_recent_emails(limit)
            
            elif choice == '2':
                email_id = int(input("Enter Email ID: "))
                viewer.view_email_details(email_id)
            
            elif choice == '3':
                viewer.view_statistics()
            
            elif choice == '4':
                print("Goodbye!")
                break
            
            else:
                print("Invalid choice!")

    except FileNotFoundError:
        print("Error: Database file not found. Run the email analyzer first.")
    except Exception as e:
        print(f"Error: {str(e)}")
