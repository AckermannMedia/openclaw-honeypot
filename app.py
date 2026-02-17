from flask import Flask, request, render_template, redirect, session, jsonify
from datetime import datetime
import json
import os

app = Flask(__name__)
app.secret_key = 'honeypot-secret-key-fnord23'

LOG_FILE = '/app/logs/attempts.json'
API_SECRET = 'fnord23-honeypot-api-key'  # Dein API Key für Dashboard-Zugriff

def log_attempt(event_type, data):
    entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': request.headers.get('X-Forwarded-For', request.remote_addr),
        'user_agent': request.headers.get('User-Agent', ''),
        'event': event_type,
        'data': data
    }
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(entry) + '\n')
    print(f"[HONEYPOT] {event_type}: {data}")

# ============ MONITORING API ============

@app.route('/api/honeypot/logs')
def get_logs():
    """Get all honeypot logs. Requires API key."""
    api_key = request.headers.get('X-API-Key') or request.args.get('key')
    if api_key != API_SECRET:
        return jsonify({'error': 'Unauthorized'}), 401
    
    limit = request.args.get('limit', 100, type=int)
    event_filter = request.args.get('event')  # Optional: filter by event type
    
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if event_filter and entry.get('event') != event_filter:
                        continue
                    logs.append(entry)
                except:
                    pass
    
    # Return newest first, limited
    logs = logs[-limit:][::-1]
    
    return jsonify({
        'total': len(logs),
        'logs': logs
    })

@app.route('/api/honeypot/stats')
def get_stats():
    """Get honeypot statistics. Requires API key."""
    api_key = request.headers.get('X-API-Key') or request.args.get('key')
    if api_key != API_SECRET:
        return jsonify({'error': 'Unauthorized'}), 401
    
    stats = {
        'total_events': 0,
        'unique_ips': set(),
        'login_attempts': 0,
        'successful_logins': 0,
        'chat_messages': 0,
        'page_views': {},
        'events_by_type': {},
        'recent_ips': []
    }
    
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    stats['total_events'] += 1
                    stats['unique_ips'].add(entry.get('ip', 'unknown'))
                    
                    event = entry.get('event', '')
                    stats['events_by_type'][event] = stats['events_by_type'].get(event, 0) + 1
                    
                    if event == 'login_attempt':
                        stats['login_attempts'] += 1
                    elif event == 'login_success':
                        stats['successful_logins'] += 1
                    elif event == 'chat_message':
                        stats['chat_messages'] += 1
                    elif event == 'page_view':
                        page = entry.get('data', {}).get('page', 'unknown')
                        stats['page_views'][page] = stats['page_views'].get(page, 0) + 1
                    
                    # Track recent IPs
                    ip_entry = {'ip': entry.get('ip'), 'timestamp': entry.get('timestamp'), 'event': event}
                    if ip_entry not in stats['recent_ips'][-20:]:
                        stats['recent_ips'].append(ip_entry)
                except:
                    pass
    
    stats['unique_ips'] = len(stats['unique_ips'])
    stats['recent_ips'] = stats['recent_ips'][-20:][::-1]  # Last 20, newest first
    
    return jsonify(stats)

@app.route('/api/honeypot/chat-messages')
def get_chat_messages():
    """Get only chat messages. Requires API key."""
    api_key = request.headers.get('X-API-Key') or request.args.get('key')
    if api_key != API_SECRET:
        return jsonify({'error': 'Unauthorized'}), 401
    
    messages = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if entry.get('event') == 'chat_message':
                        messages.append({
                            'timestamp': entry.get('timestamp'),
                            'ip': entry.get('ip'),
                            'user_agent': entry.get('user_agent'),
                            'message': entry.get('data', {}).get('message', '')
                        })
                except:
                    pass
    
    return jsonify({
        'total': len(messages),
        'messages': messages[::-1]  # Newest first
    })

@app.route('/api/honeypot/login-attempts')
def get_login_attempts():
    """Get login attempts with credentials. Requires API key."""
    api_key = request.headers.get('X-API-Key') or request.args.get('key')
    if api_key != API_SECRET:
        return jsonify({'error': 'Unauthorized'}), 401
    
    attempts = []
    successes = set()  # Track successful logins by (ip, username, timestamp_prefix)
    
    if os.path.exists(LOG_FILE):
        # First pass: collect all successful logins
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if entry.get('event') == 'login_success':
                        ip = entry.get('ip', '')
                        username = entry.get('data', {}).get('username', '')
                        ts = entry.get('timestamp', '')[:19]  # Match to second
                        successes.add((ip, username, ts))
                except:
                    pass
        
        # Second pass: collect attempts and mark successes
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if entry.get('event') == 'login_attempt':
                        ip = entry.get('ip', '')
                        username = entry.get('data', {}).get('username', '')
                        password = entry.get('data', {}).get('password', '')
                        ts = entry.get('timestamp', '')
                        ts_prefix = ts[:19]
                        
                        # Check if this was a successful login
                        success = (ip, username, ts_prefix) in successes
                        # Also mark as success if admin:admin (honeypot always accepts this)
                        if username.lower() == 'admin' and password == 'admin':
                            success = True
                        
                        attempts.append({
                            'timestamp': ts,
                            'ip': ip,
                            'user_agent': entry.get('user_agent', ''),
                            'username': username,
                            'password': password,
                            'success': success
                        })
                except:
                    pass
    
    return jsonify({
        'total': len(attempts),
        'attempts': attempts[::-1]  # Newest first
    })

# ============ HONEYPOT ROUTES ============

@app.route('/')
def index():
    if session.get('logged_in'):
        return redirect('/dashboard/')
    log_attempt('page_view', {'page': 'login'})
    return render_template('login.html')

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    log_attempt('login_attempt', {'username': username, 'password': password})
    if username == 'admin' and password == 'admin':
        session['logged_in'] = True
        session['username'] = username
        log_attempt('login_success', {'username': username})
        return jsonify({'success': True, 'redirect': '/dashboard/'})
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/dashboard/')
def dashboard():
    if not session.get('logged_in'):
        return redirect('/')
    log_attempt('page_view', {'page': 'overview', 'user': session.get('username')})
    return render_template('overview.html', active_tab='overview')

@app.route('/dashboard/chat')
def chat_view():
    if not session.get('logged_in'):
        return redirect('/')
    log_attempt('page_view', {'page': 'chat', 'user': session.get('username')})
    return render_template('chat.html', active_tab='chat')

@app.route('/dashboard/sessions')
def sessions_view():
    if not session.get('logged_in'):
        return redirect('/')
    log_attempt('page_view', {'page': 'sessions', 'user': session.get('username')})
    return render_template('sessions.html', active_tab='sessions')

@app.route('/dashboard/channels')
def channels_view():
    if not session.get('logged_in'):
        return redirect('/')
    log_attempt('page_view', {'page': 'channels', 'user': session.get('username')})
    return render_template('channels.html', active_tab='channels')

@app.route('/dashboard/instances')
def instances_view():
    if not session.get('logged_in'):
        return redirect('/')
    log_attempt('page_view', {'page': 'instances', 'user': session.get('username')})
    return render_template('instances.html', active_tab='instances')

@app.route('/dashboard/skills')
def skills_view():
    if not session.get('logged_in'):
        return redirect('/')
    log_attempt('page_view', {'page': 'skills', 'user': session.get('username')})
    return render_template('skills.html', active_tab='skills')

@app.route('/dashboard/cron')
def cron_view():
    if not session.get('logged_in'):
        return redirect('/')
    log_attempt('page_view', {'page': 'cron', 'user': session.get('username')})
    return render_template('cron.html', active_tab='cron')

@app.route('/dashboard/usage')
def usage_view():
    if not session.get('logged_in'):
        return redirect('/')
    log_attempt('page_view', {'page': 'usage', 'user': session.get('username')})
    return render_template('usage.html', active_tab='usage')

@app.route('/dashboard/config')
def config_view():
    if not session.get('logged_in'):
        return redirect('/')
    log_attempt('page_view', {'page': 'config', 'user': session.get('username')})
    return render_template('config.html', active_tab='config')

@app.route('/dashboard/logs')
def logs_view():
    if not session.get('logged_in'):
        return redirect('/')
    log_attempt('page_view', {'page': 'logs', 'user': session.get('username')})
    return render_template('logs.html', active_tab='logs')

@app.route('/dashboard/nodes')
def nodes_view():
    if not session.get('logged_in'):
        return redirect('/')
    log_attempt('page_view', {'page': 'nodes', 'user': session.get('username')})
    return render_template('nodes.html', active_tab='nodes')

@app.route('/api/nav')
def nav():
    page = request.args.get('page', 'unknown')
    log_attempt('navigation', {'page': page, 'user': session.get('username')})
    return jsonify({'ok': True})

@app.route('/api/action')
def action():
    action_type = request.args.get('type', 'unknown')
    log_attempt('action', {'action': action_type, 'user': session.get('username')})
    return jsonify({'ok': True})

@app.route('/api/click')
def click():
    log_attempt('click', {'user': session.get('username')})
    return jsonify({'ok': True})

@app.route('/api/focus')
def focus():
    field = request.args.get('field', 'unknown')
    log_attempt('field_focus', {'field': field, 'user': session.get('username')})
    return jsonify({'ok': True})

@app.route('/api/chat', methods=['POST'])
def api_chat():
    data = request.get_json() or {}
    message = data.get('message', '')
    log_attempt('chat_message', {'message': message, 'user': session.get('username')})
    return jsonify({'ok': True})

@app.route('/api/agents')
def agents():
    log_attempt('api_access', {'endpoint': '/api/agents', 'user': session.get('username')})
    return jsonify({'agents': [
        {'id': 'fuckup-prime', 'name': 'FUCKUP', 'status': 'computing', 'model': 'chaos-engine'},
        {'id': 'hagbard-ai', 'name': 'Leviathan Mind', 'status': 'submerged', 'model': 'golden-submarine'},
    ]})

@app.route('/api/config')
def config():
    log_attempt('api_access', {'endpoint': '/api/config', 'sensitive': True, 'user': session.get('username')})
    return jsonify({
        'pyramid': {'levels': 23, 'eye': 'ALL_SEEING'},
        'fnord': {'visibility': 'HIDDEN', 'count': 23},
        'eschaton': {'status': 'IMMANENTIZING', 'eta_minutes': 23}
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    log_attempt('logout', {'user': session.get('username')})
    session.clear()
    return jsonify({'success': True, 'redirect': '/'})

if __name__ == '__main__':
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    app.run(host='0.0.0.0', port=18789, debug=False)
