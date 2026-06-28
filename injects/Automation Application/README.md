# Screenshot → CCDC Inject

Local helper to turn **screenshots of security tools** (nmap, sqlmap, Burp, etc.) into a **fully-written CCDC inject memo** using n8n and Gemini.

You send:

- a PNG screenshot (HTTP body, binary), and  
- query params: `team`, `inject_name`, `inject_id`

You get back:

- `inject_text` – a complete memo in your inject template (Team / Inject / analysis / impact / recommendation / figure caption).

---

## 1. Requirements

- Linux box (your CCDC workstation is fine)
- Docker
- [Google AI Studio](https://aistudio.google.com) API key (Gemini 3 Pro)
- `jq` CLI (`sudo apt install jq`)

---

## 2. Run n8n

```bash
docker run -it --rm \
  --network host \
  -v ~/n8n_data:/home/node/.n8n \
  -e N8N_SECURE_COOKIE=false \
  -e N8N_DIAGNOSTICS_ENABLED=false \
  -e N8N_VERSION_NOTIFICATIONS_ENABLED=false \
  -e N8N_TEMPLATES_ENABLED=false \
  -e N8N_HIRING_BANNER_ENABLED=false \
  n8nio/n8n
```
Open the editor at: http://localhost:5678
Create a Google Gemini credential with your API key.

Workflow structure

Canvas nodes:

Webhook

Method: POST

Path: ccdc-image

Authentication: None (local only)

Respond: When Last Node Finishes

Response Data: First Entry JSON

Options → Binary Data = ON, Binary Property Name = image

Analyze an image (Google Gemini)

Credential: your Gemini API key

Resource: Image

Operation: Analyze Image

Model: models/gemini-3-pro-preview (or newer)

Text Input: prompt that asks for JSON with
tool, what_it_shows, host_or_url, key_findings[], impact, recommendation

Input Type: Binary File(s)

Input Data Field Name(s): image

Simplify Output: ON

Code (JavaScript)

Mode: run once for all items

Reads:

Gemini JSON from the current item

team, inject_name, inject_id from {{$node["Webhook"].json.query}}

Builds full inject text:
```
Team: <team>

Inject Name: <inject_name>

Inject ID: <inject_id>

<short blurb>

Technical Analysis
- key finding 1
- key finding 2
...

Impact and Recommendations
**Impact:** ...
**Recommendation:** ...

Device
<host_or_url>

Service
<first key finding>

Analysis of Vulnerabilities
- key finding 1
- key finding 2
...

<picture>

Figure #: Screenshot of <tool> output against <host_or_url> showing key evidence...
```
Returns
```
return [{ json: { parsed: data, inject_text: inject } }];
```
Usage
```
curl -s \
  "http://localhost:5678/webhook-test/ccdc-image?team=Team+10&inject_name=Technical+Inject+1:+Web+Server+Enumeration&inject_id=TI-01" \
  -H "Content-Type: image/png" \
  --data-binary "@/path/to/name.png" \
  | jq -r '.inject_text' \
  > inject_TI-01.md
```
Screenshots:

Look at image.png.
