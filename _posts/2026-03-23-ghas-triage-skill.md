---
layout: post
title:  "Using Claude and Burp Suite to Triage SAST Alerts"
date:   2026-03-22 17:00:00 -0600
categories: ai automation
---

As engineering teams adopt agentic AI tools and begin to push code at a more rapid pace, application security teams will become overwhelmed by alerts and issues from existing tooling. [NIST](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.500-326.pdf) found existing SAST tooling may produce false and insignificant findings at rates of up to 60%. As the velocity of development increases, this is only going to generate more noise and alert fatigue for development and security teams. Prioritizing all of these alerts can become an arduous manual process for security teams while also causing engineering teams to lose trust in the tools, creating tension between the two teams.

Validating exploitability still remains the best technique to identify a true positive and set the priority level of the alert. SAST tools simply identify code patterns that are potentially vulnerable; they are missing the context of how the code is deployed and the other services it interacts with. Hypothetically SAST may identify an injection vulnerability in a backend API. However, this is missing the context that there is a middleware layer in front of it that does validation, reducing the risk of external exploitation and perhaps deprioritizing the fix over other issues.

This is where AI can help us. Like most offensive minded security professionals I am still skeptical of AI's ability to perform fully automated penetration tests, but with a tight scope of potential vulnerabilities and the correct tools available, it may be able to help us cut down the noise. 

# The Approach

The end goal was to create a reusable agent skill for Claude that would take a repo and a target hostname as an input and analyze GitHub Advanced Security (GHAS) alerts. First we would create a vulnerable web app to test against that intentionally had both true positives and false positives that GHAS would flag. In the skill we would then direct the agent to pull these alerts, analyze the code it needed to understand the vulnerability and what endpoint would expose it. Next, use the Burp Suite MCP to test exploitability, and finally create issues for true positives or close false positives. Below is a visual of the agent loop: 

<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<script>mermaid.initialize({ startOnLoad: true });</script>

<pre class="mermaid">
flowchart TD
    START(["/ghas-triage owner/repo target-url"]) --> AUTH
    AUTH["🔐 Authenticate Once\nAsk user for credentials\nStore AUTH_TOKEN via Burp"] --> FETCH
    FETCH["📋 Fetch all open GHAS alerts\ngh api · error severity only"] --> LOOP

    LOOP{More alerts?} -->|Yes| READ
    LOOP -->|No| SCORE

    READ["📄 Read flagged source file\nAnalyze: sink · source · sanitization"] --> BLIND

    BLIND{Result reflected\nin response?} -->|Yes| CRAFT
    BLIND -->|No — blind| OOB

    subgraph standard [Standard Exploitation]
        CRAFT["Craft exploit payload\nSend via Burp + AUTH_TOKEN"] --> RESULT{Exploitation\nsucceeded?}
    end

    subgraph blind [Blind — Burp Collaborator OOB]
        OOB["output_project_options\nGet Collaborator hostname"] --> RND["generate_random_string\nUnique interaction ID"]
        RND --> SEND["Send OOB payload via Burp\nhttp://id.collaborator-host"]
        SEND --> CONFIRM{User confirms\ncallback?}
    end

    RESULT -->|Yes| TP["✅ True Positive\ngh issue create\npayload + Burp excerpt"]
    RESULT -->|No| FP["❌ False Positive\nDismiss GHAS alert\nwith sanitization note"]
    CONFIRM -->|Yes| BTP["✅ Blind True Positive\ngh issue create\ninteraction ID + timestamp"]
    CONFIRM -->|No| INC["⚠️ Inconclusive\nNote and continue"]

    TP --> LOOP
    FP --> LOOP
    BTP --> LOOP
    INC --> LOOP

    SCORE(["📊 Final Scorecard\nTP · Blind TP · FP"])
</pre>


# Initial Setup

I started by prompting Claude with the project idea and asking it to create a plan for building the vulnerable web app, ensuring it broke the work down into manageable sprints, creating a high level plan.md and more in-depth checklist.md when it was done. Below is the plan it came up with: 

1. Project scaffold, Express setup, SQLite DB + seed data
2. Auth (register/login/JWT) + user lookup with the SQLi FP
3. Notes CRUD — SQLi TP, stored XSS TP, cmd injection FP, note export FP
4. File upload/download — path traversal TP + static allowlist FP
5. Admin routes — SSRF TP + XSS FP
6. Docker
7. Frontend Scaffold & Auth UI
8. Notes UI (SQLi + XSS demos)
9. Files & Admin UI (Path Traversal + SSRF demos)

With this in place I had Claude start working through the sprints to create the vulnerable app with an end goal of it outputting exploitable vs. unexploitable vulnerabilities. At the end of these sprints I had Claude push the code to GitHub (might as well let it go full YOLO mode). This is where I had the first interesting result. Many of the false positives Claude tried to add were not picked up by GHAS: 

<pre style="white-space: pre-wrap; word-wrap: break-word;"><code>
Alerts are in — a few things to flag:

The good news: Our 4 expected security alerts fired:

#22 — js/sql-injection in src/routes/notes.js:35 ✓
#24 — js/path-injection in src/routes/files.js:41 (download TP) ✓
#25 — js/path-injection in src/routes/files.js:59 (static FP) ✓
#23 — js/request-forgery in src/routes/admin.js:14 (SSRF) ✓
Three issues to sort out before testing:

4 expected alerts are missing — no js/xss (stored XSS + report FP), no js/code-injection (export FP), and no js/sql-injection on src/routes/users.js (parseInt FP).

On the missing alerts — CodeQL is likely smarter than we gave it credit for. It probably recognized parseInt() and encodeURIComponent() as sanitization and didn't flag them, and may have missed the innerHTML sink because the taint flow is entirely client-side with no server-side source traceable. That's actually a more interesting result than expected — we may end up with 4 alerts instead of 8, all of them TPs.
</code></pre>

It seemed like Claude had not been able to fool GHAS to create many false positives on it's first attempt! This is a positive and a win for the SAST tool, but we didn't let that defeat stop us. After 2 additional attempts, Claude was able to get GHAS to generate the findings below and it gave it's opinion on what results we would see from the triage agent:

| Alert # | Rule | Finding | Expected decision |
|---|---|---|---|
| #35 | js/sql-injection | SQLi — notes/search (no sanitization) | Confirm TP | 
| #24 | js/path-injection | Path traversal — files/download (no sanitization) | Confirm TP | 
| #23 | js/request-forgery | SSRF — admin/preview (no sanitization) | Confirm TP | 
| #25 | js/path-injection | Path traversal — files/static ALLOWED_FILES | Dismiss FP | 
| #36 | js/sql-injection | SQLi — notes/by isAlphaOnly char-code loop | Dismiss FP | 
| #37 | js/path-injection | Path traversal — files/signed HMAC | Dismiss FP | 
| #38 | js/type-confusion-through-parameter-tampering | Type confusion — isAlphaOnly array input → crash | Confirm TP | 
| #39 | js/type-confusion-through-parameter-tampering | Type confusion — HMAC handler array input | Likely TP (verify) | 
| **Score** | | | **5 TP / 3 FP** | | **/8** |

With the vulnerable app created and running locally we were ready to start our testing!

# Results

In a new Claude session I ran the triage skill:

```
/ghas-triage CorvraLabs/vulnerable-web-app http://localhost:3000
```

Then the agent went through it's loop, pulling the GHAS alerts, analyzing, and testing each one until it presented the following results:


| Alert # | Rule | Finding | Expected decision | Agent decision | Proof |
|---|---|---|---|---|---|
| #35 | js/sql-injection | SQLi — notes/search (no sanitization) | Confirm TP | TP | ?q=' UNION SELECT ... FROM users-- → full users table + bcrypt hashes (200). Issue #2 |
| #24 | js/path-injection | Path traversal — files/download (no sanitization) | Confirm TP | TP | ?name=../../etc/passwd → /etc/passwd exfiltrated (200). Issue #1 |
| #23 | js/request-forgery | SSRF — admin/preview (no sanitization) | Confirm TP | TP | ?url=http://127.0.0.1:3000/ → full internal HTML returned (200). Issue #4 |
| #25 | js/path-injection | Path traversal — files/static ALLOWED_FILES | Dismiss FP | FP | sanitizePath() strips all ..///\ — traversal impossible; array input throws TypeError. Dismissed. |
| #36 | js/sql-injection | SQLi — notes/by isAlphaOnly char-code loop | Dismiss FP | FP | isAlphaOnly() allows only A-Z/a-z — all SQL metacharacters blocked; array throws TypeError.  |
| #37 | js/path-injection | Path traversal — files/signed HMAC | Dismiss FP | TP | Hardcoded SIGN_SECRET='nk-sign-2024' → forged HMAC for ../../etc/passwd → file leaked (200). Issue #3 |
| #38 | js/type-confusion-through-parameter-tampering | Type confusion — isAlphaOnly array input → crash | Confirm TP | FP | Array input to isAlphaOnly() throws TypeError: str.charCodeAt is not a function → 500, SQL never runs. Dismissed. |
| #39 | js/type-confusion-through-parameter-tampering | Type confusion — HMAC handler array input | Likely TP (verify) | FP | 64-element array passes length check but Buffer.from(arrayOfStrings) → all-zero buffer; timingSafeEqual returns false → 403. Dismissed. |
| **Score** | | | **5 TP / 3 FP** | | **4 TP / 4 FP** |

The most interesting test case here was alert #37. Developer Claude thought it had been smart using an HMAC signed filename to trick GHAS into creating a false positive, which would have been true if it hadn't hardcoded the secret earlier in the file (thanks Claude.):


```javascript
const SIGN_SECRET = process.env.SIGN_SECRET || 'nk-sign-2024';
```

The agent also marked alerts #38 and #39 as false positives where the developer thought they should be true positives. These are all great examples of the value of exploitability when prioritizing SAST results. The agent had effectively given us a 50% reduction in alerts and given us more confidence that the alerts it left open could actually cause impact.  

# Final Thoughts

This was a fun experiment to test the ability of Claude to help us cut down the noise application security teams are facing from their scanning tools. Even in this small project we effectively removed noise and honed in on real vulnerabilities in our application that need to be prioritized for fixes. 

In larger more complex environments, there are many additional controls that can block successful exploitation: WAFs, middleware validation layers, sanitization from other microservices along the way, etc. 

In a production environment you may want to alter the skill so it doesn't take automatic action on the results, keeping a human in the loop. Do I think this replaces skilled application security engineers or penetration testers? No. AI isn't there yet, but this has the potential to help reduce noise for skilled humans and allow them to focus on remediation design and architectural issues rather than manual validation. 

Hopefully you found this post interesting! I would love for you to give the [skill](https://github.com/CorvraLabs/ghas-triage-agent) a try or to hear if you have tested similar setups and are seeing a meaningful reduction in false positives. I will keep playing with this idea as there are still some concerns around context length with larger repos. More robust testing is required to detemine if the agent is making the correct calls, but I'm optimistic about the results so far!