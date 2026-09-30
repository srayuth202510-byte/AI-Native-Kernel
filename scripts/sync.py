#!/usr/bin/env python3
import json
import os
import re

def replace_marked_section(text, start_marker, end_marker, new_content,
                           allowed_headings, allowed_literals=()):
    """Replace a marker-delimited block, refusing to drop hand-written content.

    Everything between the markers is regenerated from tasks.json, so any line
    the generator cannot reproduce would be silently lost. That has already
    happened once (the "Hardening Round" sections lived inside the block and
    were erased on every run). Bail out loudly instead.
    """
    start_re = re.escape(start_marker)
    end_re = re.escape(end_marker)
    pattern = re.compile(f'{start_re}.*?{end_re}', re.DOTALL)

    match = pattern.search(text)
    if not match:
        print(f"Warning: {start_marker} / {end_marker} markers not found, section left untouched")
        return text

    existing = match.group(0)
    body = existing[len(start_marker):-len(end_marker)]

    in_fence = False
    for line in body.split('\n'):
        stripped = line.strip()
        if stripped.startswith('```'):
            in_fence = not in_fence
            continue
        # Inside a fenced block the content is a literal payload (command list),
        # not prose — only fence state matters, not individual lines.
        if in_fence or not stripped:
            continue
        if stripped.startswith('### '):
            if stripped[4:] not in allowed_headings:
                raise SystemExit(
                    f"Refusing to sync: hand-written heading {stripped!r} found inside "
                    f"the {start_marker} block. Move it below {end_marker} first."
                )
            continue
        if stripped in allowed_literals:
            continue
        if not stripped.startswith('- '):
            raise SystemExit(
                f"Refusing to sync: line {stripped[:60]!r} inside the {start_marker} "
                f"block is not generated from tasks.json and would be lost. "
                f"Move it below {end_marker} first."
            )

    replacement = f'{start_marker}\n{new_content}\n{end_marker}'
    return text[:match.start()] + replacement + text[match.end():]


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
        "immune-system",
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
        "- Re-validate with the pinned local toolchain from `scripts/use-local-toolchain.sh` when the environment changes."
    ]
    for t in blocked_tasks:
        desc = t.get("desc", "").strip()
        desc_str = f" - {desc}" if desc else ""
        validation_parts.append(f"- **Blocked: [{t['id']}] {t['title']}**{desc_str}")
        
    validation_parts.extend([
        "- Recommended verification commands:\n",
        "```bash",
        "cargo fmt --all -- --check",
        "cargo check --workspace",
        "cargo clippy --workspace -- -D warnings",
        "cargo test --workspace",
        "```"
    ])
    
    validation_content = "\n".join(validation_parts).strip()
    
    # Replace sections in MD
    status_md = replace_marked_section(
        status_md,
        '<!-- IMPLEMENTED_NOW_START -->',
        '<!-- IMPLEMENTED_NOW_END -->',
        implemented_now_content,
        allowed_headings=set(modules_order),
    )
    
    status_md = replace_marked_section(
        status_md,
        '<!-- NOT_IMPLEMENTED_YET_START -->',
        '<!-- NOT_IMPLEMENTED_YET_END -->',
        not_implemented_content,
        allowed_headings=set(),
    )
    
    status_md = replace_marked_section(
        status_md,
        '<!-- VALIDATION_STATUS_START -->',
        '<!-- VALIDATION_STATUS_END -->',
        validation_content,
        allowed_headings=set(),
        allowed_literals={'```bash', '```'},
    )
    
    with open(status_path, 'w', encoding='utf-8') as f:
        f.write(status_md)
    print("Updated obsidian_vault/implementation-status.md successfully.")

if __name__ == "__main__":
    main()
