#!/usr/bin/env python3
import http.server
import json
import os
import sys

# Add current folder to path to import sync
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(script_dir)
from sync import main as run_sync

PORT = 8000
DIRECTORY = os.path.dirname(script_dir)

class KanbanHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_POST(self):
        if self.path == '/api/save':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
                
                # Path to tasks.json
                tasks_path = os.path.join(DIRECTORY, "docs", "tasks.json")
                
                # Write to tasks.json
                tasks_list = data if isinstance(data, list) else data.get("tasks", [])
                with open(tasks_path, 'w', encoding='utf-8') as f:
                    json.dump(tasks_list, f, indent=2, ensure_ascii=False)
                
                # Run sync
                run_sync()
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success"}).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

def run():
    # Change working dir to repo root so relative paths work
    os.chdir(DIRECTORY)
    server_address = ('', PORT)
    httpd = http.server.HTTPServer(server_address, KanbanHandler)
    print(f"=========================================================")
    print(f"🚀 AI-Native Kernel Kanban Server started at http://localhost:{PORT}")
    print(f"📁 Serving files from: {DIRECTORY}")
    print(f"👉 Open in browser: http://localhost:{PORT}/docs/board.html")
    print(f"📝 Edits in browser will automatically sync to docs/tasks.json")
    print(f"   and obsidian_vault/implementation-status.md in real-time!")
    print(f"=========================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Kanban Server.")

if __name__ == '__main__':
    run()
