from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import subprocess
import os
import re
import logging
from pathlib import Path
from datetime import timedelta

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Configure app and CSRF protection
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Basic config only
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

TOPOLOGY_DIR = Path('/root/nokia-basic-dci-lab/').resolve()

def validate_topology_file(filename):
    """Validate topology file path"""
    if not filename or '..' in filename:
        return False
    file_path = TOPOLOGY_DIR / filename
    return file_path.is_file() and file_path.suffix in ('.yml', '.yaml')

@app.route('/')
def index():
    try:
        topology_files = [f for f in os.listdir(TOPOLOGY_DIR) if f.endswith(('.yml', '.yaml'))]
        return render_template('index.html', 
                             topology_files=topology_files, 
                             topo_selected='topo_file' in session)
    except Exception as e:
        logging.error(f"Error in index route: {e}")
        flash('Error loading topology files', 'error')
        return redirect(url_for('index'))

# Error handlers
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    logging.error(f"CSRF error: {e}")
    return render_template('error.html', message="CSRF token missing or invalid"), 400

@app.route('/set-topology', methods=['POST'])
def set_topology():
    try:
        topo_file = request.form.get('topo_file')
        if not topo_file:
            flash('No topology file selected', 'error')
            return redirect(url_for('index'))

        if validate_topology_file(topo_file):
            topo_path = str(TOPOLOGY_DIR / topo_file)
            session['topo_file'] = topo_path
            flash('Topology file selected successfully', 'success')
        else:
            flash('Invalid topology file selected', 'error')
    except Exception as e:
        logging.error(f"Error setting topology: {e}")
        flash('Error setting topology file', 'error')
    
    return redirect(url_for('index'))

def run_fcli_command(command):
    """Run command with error handling"""
    try:
        logging.info(f"Executing command: {' '.join(command)}")
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=30
        )
        output = result.stdout.strip()
        if output.endswith("\x1b[0m"):
            output = output[:-4]
        return output
    except subprocess.TimeoutExpired:
        logging.error("Command execution timed out")
        return "Error: Command execution timed out"
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e.stderr}")
        return f"Error executing command: {e.stderr}"
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return f"Unexpected error occurred: {str(e)}"

def process_filter_option(filter_value):
    """
    Splits a comma-separated list (e.g. "ni=default,prefix=1.11.21.11/32")
    into ["ni=default", "prefix=1.11.21.11/32"].
    """
    if not filter_value:
        return []
    return [f.strip() for f in filter_value.split(',') if f.strip()]

def format_command_output(output):
    """Format command output as string"""
    return output

@app.route('/command/<cmd>', methods=['GET', 'POST'])
def command(cmd):
    if not session.get('topo_file'):
        flash('Please select a topology file first', 'error')
        return redirect(url_for('index'))
    
    topo_file = session.get('topo_file')
    if not topo_file:
        flash('Please select a topology file first.')
        return redirect(url_for('index'))
    
    help_command = ['fcli', '-t', topo_file, cmd, '--help']
    help_output = run_fcli_command(help_command)
    options = parse_help_output(help_output)
    
    if request.method == 'POST':
        data = request.get_json()
        options_input = data.get('options', {})
        cmd_args = ['fcli', '-t', topo_file, cmd]

        # Build the fcli command with generic filter handling
        for option, value in options_input.items():
            if option == '-f':
                for flt in process_filter_option(value):
                    cmd_args += ['-f', flt]
            else:
                cmd_args += [option, value]

        output = run_fcli_command(cmd_args)
        parsed_output = parse_ascii_table(output)
        
        if isinstance(parsed_output, str):
            return jsonify({'output': parsed_output})
        else:
            return jsonify({
                'headers': parsed_output['headers'],
                'data': parsed_output['data']  # Ensure 'Node' is included in data
            })
    
    return render_template('command.html', command=cmd, options=options)

def parse_help_output(help_output):
    options = []
    # Updated pattern to split on comma and take first option
    option_pattern = re.compile(r'  (-[\w-]+)(?:,\s+--[\w-]+)?\s+(.+)$', re.MULTILINE)
    for match in option_pattern.finditer(help_output):
        options.append({
            'option': match.group(1).strip(),  # Take only first option without comma
            'description': match.group(2).strip()
        })
    return options

def parse_ascii_table(output):
    """Parse ASCII table into structured data"""
    lines = output.split('\n')
    # Remove the last two lines
    lines = lines[:-2]
    # Find the header rows and separator line
    header_rows = []
    separator_idx = -1
    for i, line in enumerate(lines):
        if '═' in line:
            separator_idx = i
            break
        if '│' in line:
            header_rows.append(line)
    
    if not header_rows or separator_idx == -1:
        return output  # Return original if not a table
    
    # Parse headers
    headers = []
    for col in zip(*[row.split('│')[0:] for row in header_rows]):
        header = ' '.join(part.strip() for part in col if part.strip())
        headers.append(header.lower())  # Convert headers to lowercase
    
    # Ensure 'node' is the first header
    if 'node' in headers:
        headers.remove('node')
        headers.insert(0, 'node')
    else:
        headers.insert(0, 'node')  # Add 'node' if not present
    
    # Parse data rows
    data = []
    current_node = None
    last_known_node = None
    last_known_ni = None

    for line in lines[separator_idx + 1:]:
        if not line.strip() or '─' in line:
            continue
        cols = [col.strip() for col in line.split('│')[0:]]  # Include the last column
        if len(cols) < len(headers):
            cols.append(line.split('│')[-1].strip())  # Add the last column if missing
        if cols:
            if len(cols) < len(headers):
                if current_node is None:
                    current_node = 'unknown'
                cols.insert(0, current_node)
            else:
                current_node = cols[0]
            row_dict = {header: col for header, col in zip(headers, cols)}

            # Fill empty 'node' or 'ni' with last non-empty values
            if 'node' in row_dict:
                if not row_dict['node'].strip():
                    if last_known_node:
                        row_dict['node'] = last_known_node
                else:
                    last_known_node = row_dict['node']

            if 'ni' in row_dict:
                if not row_dict['ni'].strip():
                    if last_known_ni:
                        row_dict['ni'] = last_known_ni
                else:
                    last_known_ni = row_dict['ni']

            data.append(row_dict)
    return {
        "headers": headers,
        "data": data
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)