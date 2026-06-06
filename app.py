from flask import Flask, render_template, request, send_file
import requests
from datetime import datetime
import ipaddress
import re
import time
import csv
import io

# Use project root for templates so existing index.html is found
app = Flask(__name__, template_folder='.')

VT_API_KEY = '6c204622b36282aec2ad2c4e1aeed173fcea8564d70a049ea84e270d62a55337'
ABUSE_API_KEY = '5a20f53a1ffff64fb027ddea64514244d2b9d02d182f5e9bae4080f35a01acb421c4ff9147226bd4'

latest_results = []

def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def is_sha1(value):
    return bool(re.fullmatch(r'[a-fA-F0-9]{40}', value))

def get_vt_info(value):
    if is_ip(value):
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{value}'
    elif is_sha1(value):
        url = f'https://www.virustotal.com/api/v3/files/{value}'
    else:
        url = f'https://www.virustotal.com/api/v3/domains/{value}'

    headers = {'x-apikey': VT_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()['data']['attributes']
        stats = data.get('last_analysis_stats', {})
        detection_ratio = f"{stats.get('malicious', 0)} / {sum(stats.values())}"

        raw_date = data.get('creation_date', None)
        if raw_date and str(raw_date).isdigit():
            registration_date = datetime.utcfromtimestamp(int(raw_date)).strftime('%Y-%m-%d')
        else:
            registration_date = 'Not available'

        return detection_ratio, registration_date
    else:
        return 'Error', f"Error {response.status_code}"

def get_abuse_info(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    headers = {
        'Accept': 'application/json',
        'Key': ABUSE_API_KEY
    }
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()['data']
        return {
            'abuse_score': data.get('abuseConfidenceScore', 'N/A'),
            'abuse_domain': data.get('domain', 'N/A'),
            'country_code': data.get('countryCode', 'N/A'),
            'usage_type': data.get('usageType', 'N/A')
        }
    else:
        return {
            'abuse_score': f"Error {response.status_code}",
            'abuse_domain': 'N/A',
            'country_code': 'N/A',
            'usage_type': 'N/A'
        }

@app.route('/', methods=['GET', 'POST'])
def index():
    global latest_results
    results = []
    if request.method == 'POST':
        inputs = request.form.get('inputs', '')
        entries = [e.strip() for e in inputs.splitlines() if e.strip()]
        for i, entry in enumerate(entries):
            if i > 0:
                time.sleep(15)  # VT rate limit: 4 requests/minute

            detection_ratio, registration_date = get_vt_info(entry)
            abuse_data = get_abuse_info(entry) if is_ip(entry) else {
                'abuse_score': 'N/A',
                'abuse_domain': 'N/A',
                'country_code': 'N/A',
                'usage_type': 'N/A'
            }

            results.append({
                'input': entry,
                'detection_ratio': detection_ratio,
                'registration_date': registration_date,
                'abuse_score': abuse_data['abuse_score'],
                'abuse_domain': abuse_data['abuse_domain'],
                'country_code': abuse_data['country_code'],
                'usage_type': abuse_data['usage_type']
            })
        latest_results = results
    return render_template('index.html', results=results)

@app.route('/download')
def download_csv():
    global latest_results
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'input', 'detection_ratio', 'registration_date',
        'abuse_score', 'abuse_domain', 'country_code', 'usage_type'
    ])
    writer.writeheader()
    for row in latest_results:
        writer.writerow(row)

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='lookup_results.csv'
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)