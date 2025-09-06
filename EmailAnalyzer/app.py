import os
import subprocess
from flask import Flask, request, redirect, url_for, send_from_directory, render_template

app = Flask(__name__, template_folder='templates', static_folder='static')
UPLOAD_FOLDER = 'uploads'
REPORT_FOLDER = 'reports'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORT_FOLDER'] = REPORT_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(REPORT_FOLDER):
    os.makedirs(REPORT_FOLDER)

@app.route('/') #decorator's
def upload_file_form():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'filee' not in request.files:
        return "No file part"
    file = request.files['filee']
    if file.filename == '':
        return "No selected file"
    if file:
        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)

        file.save(filename)
        
        output_path = os.path.join(app.config['REPORT_FOLDER'], 'report.html')

        result = subprocess.run(['python', 'email-analyzer.py', '-f', filename, '-o', output_path], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(result.stdout)
            return redirect(url_for('show_report', filename='report.html'))
        else:
            print(result.stderr)
            return "An error occurred while generating the report. Please check the console for details."

@app.route('/reports/<filename>')
def show_report(filename):
    try:
        return send_from_directory(app.config['REPORT_FOLDER'], filename)
    except FileNotFoundError:
        return "Report not found. Please try again."

if __name__ == '__main__':
    app.run(debug=True)

