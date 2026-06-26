#!/usr/bin/env python3
import json
import os
import re

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_dir = os.path.dirname(script_dir)
    
    tasks_path = os.path.join(repo_dir, "docs", "tasks.json")
    board_path = os.path.join(repo_dir, "docs", "board.html")
    status_path = os.path.join(repo_dir, "obsidian_vault", "implementation-status.md")
    
    # 1. Load tasks
    if not os.path.exists(tasks_path):
        print(f"Error: Central tasks file not found at {tasks_path}")
        return
        
    with open(tasks_path, 'r', encoding='utf-8') as f:
        tasks = json.load(f)
        
    # Find next sequence ID number
    max_id_num = 0
    for t in tasks:
        id_str = t.get("id", "")
        match = re.search(r'\d+', id_str)
        if match:
            max_id_num = max(max_id_num, int(match.group()))
            
    # 2. Update docs/board.html
    if not os.path.exists(board_path):
        print(f"Error: Board file not found at {board_path}")
        return
        
    with open(board_path, 'r', encoding='utf-8') as f:
        board_html = f.read()
        
    # Format tasks JSON to align nicely inside JS
    seed_json = json.dumps(tasks, indent=4, ensure_ascii=False)
    
    start_marker = "// SEED_START"
    end_marker = "// SEED_END"
    start_idx = board_html.find(start_marker)
    end_idx = board_html.find(end_marker)
    
    if start_idx != -1 and end_idx != -1:
        new_seed_block = f"\nconst SEED = {seed_json};\n"
        board_html = board_html[:start_idx + len(start_marker)] + new_seed_block + board_html[end_idx:]
    else:
        print("Warning: SEED_START or SEED_END markers not found in board.html")
        
    # Update nextSeq
    board_html = re.sub(r'nextSeq:\s*\d+', f'nextSeq: {max_id_num + 1}', board_html)
    
    with open(board_path, 'w', encoding='utf-8') as f:
        f.write(board_html)
    print("Updated docs/board.html successfully.")
    
    # 3. Update obsidian_vault/implementation-status.md
    if not os.path.exists(status_path):
        print(f"Error: Implementation status file not found at {status_path}")
        return
        
    with open(status_path, 'r', encoding='utf-8') as f:
        status_md = f.read()
        
    # Implemented Now: Grouped by module, status == "done"
    done_tasks = [t for t in tasks if t.get("status") == "done"]
    modules_order = [
        "kernel-companion",
        "agent-scheduler",
        "intent-bus",
        "context-memory",
        "compute-scheduler",
        "capability-security",
        "infra"
    ]
    
    implemented_parts = []
    # Group tasks by module
    tasks_by_module = {}
    for t in done_tasks:
        mod = t.get("module", "infra")
        if mod not in tasks_by_module:
            tasks_by_module[mod] = []
        tasks_by_module[mod].append(t)
        
    for mod in modules_order:
        mod_tasks = tasks_by_module.get(mod, [])
        if not mod_tasks:
            continue
        implemented_parts.append(f"### {mod}\n")
        for t in sorted(mod_tasks, key=lambda x: x.get("id", "")):
            desc = t.get("desc", "").strip()
            desc_str = f": {desc}" if desc else ""
            implemented_parts.append(f"- **[{t['id']}] {t['title']}**{desc_str}")
        implemented_parts.append("") # empty line after module
        
    implemented_now_content = "\n".join(implemented_parts).strip()
    
    # Not Implemented Yet: status in ["backlog", "todo", "doing", "review"]
    not_implemented_statuses = ["backlog", "todo", "doing", "review"]
    not_done_tasks = [t for t in tasks if t.get("status") in not_implemented_statuses]
    
    not_implemented_parts = []
    # Sort by status priority / id
    status_order = {"doing": 0, "review": 1, "todo": 2, "backlog": 3}
    sorted_not_done = sorted(
        not_done_tasks,
        key=lambda x: (status_order.get(x.get("status", "backlog"), 4), x.get("id", ""))
    )
    for t in sorted_not_done:
        desc = t.get("desc", "").strip()
        desc_str = f": {desc}" if desc else ""
        not_implemented_parts.append(f"- **[{t['id']}] {t['title']}** ({t.get('status')}, {t.get('priority')}){desc_str}")
        
    not_implemented_content = "\n".join(not_implemented_parts).strip()
    
    # Validation Status: status == "blocked" + static checks
    blocked_tasks = [t for t in tasks if t.get("status") == "blocked"]
    
    validation_parts = [
        "- The repository has meaningful unit tests in several crates."
    ]
    for t in blocked_tasks:
        desc = t.get("desc", "").strip()
        desc_str = f" - {desc}" if desc else ""
        validation_parts.append(f"- **Blocked: [{t['id']}] {t['title']}**{desc_str}")
        
    validation_parts.extend([
        "- Before calling this baseline stable, run:\n",
        "```bash",
        "rtk cargo fmt --all -- --check",
        "rtk cargo clippy --workspace -- -D warnings",
        "rtk cargo test --workspace",
        "```"
    ])
    
    validation_content = "\n".join(validation_parts).strip()
    
    # Replace sections in MD
    status_md = re.sub(
        r'<!-- IMPLEMENTED_NOW_START -->.*?<!-- IMPLEMENTED_NOW_END -->',
        f'<!-- IMPLEMENTED_NOW_START -->\n{implemented_now_content}\n<!-- IMPLEMENTED_NOW_END -->',
        status_md,
        flags=re.DOTALL
    )
    
    status_md = re.sub(
        r'<!-- NOT_IMPLEMENTED_YET_START -->.*?<!-- NOT_IMPLEMENTED_YET_END -->',
        f'<!-- NOT_IMPLEMENTED_YET_START -->\n{not_implemented_content}\n<!-- NOT_IMPLEMENTED_YET_END -->',
        status_md,
        flags=re.DOTALL
    )
    
    status_md = re.sub(
        r'<!-- VALIDATION_STATUS_START -->.*?<!-- VALIDATION_STATUS_END -->',
        f'<!-- VALIDATION_STATUS_START -->\n{validation_content}\n<!-- VALIDATION_STATUS_END -->',
        status_md,
        flags=re.DOTALL
    )
    
    with open(status_path, 'w', encoding='utf-8') as f:
        f.write(status_md)
    print("Updated obsidian_vault/implementation-status.md successfully.")

if __name__ == "__main__":
    main()
