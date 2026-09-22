"""Deterministic HTML report renderer (Phase 9).

Renders the same ``AssessmentReport`` section model into a standalone,
self-contained HTML document using only the Python standard library.  Like the
Markdown/JSON/PDF forms it is a pure projection of persisted state: no client
side dependencies, no JS, no invented content.

The generated document is static so any browser can print/save it as-is while
keeping the exact same reproducibility guarantees as the other exports.
"""
from __future__ import annotations

import html
import re


def _esc(text) -> str:
    return html.escape(str(text or ""))


def _inline(text: str) -> str:
    """Render inline markdown (code + bold) to safe HTML."""
    text = _esc(text)
    text = re.sub(r"`([^`]*)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    return text


def _section_html(title: str, markdown: str) -> str:
    """Convert one section's markdown into semantic HTML (deterministic)."""
    lines: list[str] = []
    lines.append(f"<section class='section'>")
    lines.append(f"<h2>{_esc(title)}</h2>")
    in_pre = False
    in_list = False

    def _close_list():
        nonlocal in_list
        if in_list:
            lines.append("</ul>")
            in_list = False

    for raw in markdown.split("\n"):
        line = raw.rstrip()
        if line.startswith("```"):
            _close_list()
            if in_pre:
                lines.append("</pre>")
                in_pre = False
            else:
                lines.append("<pre><code>")
                in_pre = True
            continue
        if in_pre:
            lines.append(_esc(line))
            continue

        if not line.strip():
            _close_list()
            continue
        stripped = line.lstrip()
        if stripped.startswith("### "):
            _close_list()
            lines.append(f"<h3>{_inline(stripped[4:])}</h3>")
        elif stripped.startswith("## "):
            _close_list()
            lines.append(f"<h3>{_inline(stripped[3:])}</h3>")
        elif re.match(r"^\s*[-*] ", line):
            if not in_list:
                lines.append("<ul>")
                in_list = True
            lines.append(f"<li>{_inline(re.sub(r'^\s*[-*] ', '', line))}</li>")
        elif re.match(r"^\s*\|", line):
            _close_list()
            cells = [c for c in line.strip().strip("|").split("|")]
            lines.append("<table>")
            for cell in cells:
                lines.append(f"<td>{_inline(cell.strip())}</td>")
            lines.append("</table>")
        else:
            _close_list()
            lines.append(f"<p>{_inline(stripped)}</p>")

    _close_list()
    if in_pre:
        lines.append("</pre>")
    lines.append("</section>")
    return "\n".join(lines)


def render_html(sections: list[dict], *, title: str, generated_at: str = "",
                fingerprint: str = "", config_fingerprint: str = "") -> str:
    """Render a standalone, self-contained HTML report document."""
    body_parts: list[str] = []
    for section in sections:
        body_parts.append(_section_html(section.get("title") or section.get("id") or "",
                                        section.get("markdown") or ""))
    body = "\n".join(body_parts)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberAgent Assessment Report — {_esc(title)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #0b0f19; color: #f1f5f9; margin: 0; padding: 0; line-height: 1.6; }}
  .doc {{ max-width: 880px; margin: 0 auto; padding: 40px 24px 80px; }}
  .head {{ border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 24px; }}
  .head h1 {{ font-size: 24px; margin: 0 0 8px; color: #e2e8f0; }}
  .head .meta {{ color: #94a3b8; font-size: 13px; }}
  .head .fp {{ font-family: Consolas, Menlo, monospace; color: #7dd3fc; }}
  section.section {{ margin-bottom: 32px; }}
  section.section h2 {{ font-size: 18px; color: #38bdf8; border-left: 3px solid #38bdf8;
                        padding-left: 10px; margin: 0 0 12px; }}
  section.section h3 {{ font-size: 15px; color: #fbbf24; margin: 16px 0 6px; }}
  p {{ margin: 0 0 10px; }}
  ul {{ margin: 0 0 10px 4px; padding-left: 20px; }}
  li {{ margin: 2px 0; }}
  code, pre {{ font-family: Consolas, Menlo, monospace; background: #0f172a;
               border: 1px solid #1e293b; border-radius: 6px; font-size: 12.5px; }}
  code {{ padding: 1px 5px; color: #a7f3d0; }}
  pre {{ padding: 12px 14px; overflow-x: auto; color: #cbd5e1; }}
  table {{ border-collapse: collapse; margin: 4px 0 12px; width: 100%; }}
  td {{ border: 1px solid #1e293b; padding: 6px 10px; font-size: 12.5px; }}
  .foot {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid #1e293b;
          color: #64748b; font-size: 12px; }}
  @media print {{ body {{ background: #ffffff; color: #121212; }}
                  .head h1 {{ color: #0f172a; }}
                  section.section h2 {{ color: #0369a1; border-left-color: #0369a1; }}
                  .head .meta {{ color: #475569; }} }}
</style>
</head>
<body>
<div class="doc">
  <div class="head">
    <h1>CyberAgent Assessment Report</h1>
    <div class="meta">Target: <strong>{_esc(title)}</strong></div>
    <div class="meta">Generated: {_esc(generated_at)}</div>
    <div class="meta">Report fingerprint: <span class="fp">{_esc(fingerprint or 'n/a')}</span></div>
    <div class="meta">Configuration fingerprint: <span class="fp">{_esc(config_fingerprint or 'n/a')}</span></div>
  </div>
{body}
  <div class="foot">
    This report is generated deterministically from persisted assessment state.
    Coverage describes the assessment performed; absence of a finding does not
    assert that an area is free of vulnerabilities outside the exercised coverage.
  </div>
</div>
</body>
</html>
"""


__all__ = ["render_html"]