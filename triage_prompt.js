(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) {
    root.TriagePrompt = api;
    root.buildDefaultIocTable = api.buildDefaultIocTable;
    root.buildTriagePrompt = api.buildTriagePrompt;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  function utf8ToBase64(text) {
    if (typeof Buffer !== 'undefined') return Buffer.from(text, 'utf8').toString('base64');
    const utf8Bytes = new TextEncoder().encode(text);
    let binary = '';
    for (let i = 0; i < utf8Bytes.length; i++) {
      binary += String.fromCharCode(utf8Bytes[i]);
    }
    return btoa(binary);
  }

  function buildDefaultIocTable(grouped) {
    const labelMap = {
      ip: 'IP Addresses', domain: 'Domains', url: 'URLs', hostname: 'Hostnames',
      hash: 'File Hashes', email: 'Email Addresses', cve: 'CVEs',
      mitre: 'MITRE Techniques', crypto: 'Crypto Addresses', mac: 'MAC Addresses'
    };
    const vtIp    = v => `[VirusTotal](https://www.virustotal.com/gui/ip-address/${encodeURIComponent(v)}) · [AbuseIPDB](https://www.abuseipdb.com/check/${encodeURIComponent(v)})`;
    const vtDom   = v => `[VirusTotal](https://www.virustotal.com/gui/domain/${encodeURIComponent(v)})`;
    const vtUrl   = v => `[VirusTotal](https://www.virustotal.com/gui/url/${utf8ToBase64(v).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')})`;
    const vtHash  = v => `[VirusTotal](https://www.virustotal.com/gui/file/${v})`;
    const noLinks = () => '—';
    const cveLinks    = v => `[NVD](https://nvd.nist.gov/vuln/detail/${v}) · [MITRE CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=${v})`;
    const mitreLinks  = v => `[ATT&CK](https://attack.mitre.org/techniques/${v.replace('.', '/')})`;
    const linkMap = {
      ip: vtIp, domain: vtDom, url: vtUrl, hostname: noLinks, hash: vtHash,
      email: noLinks, cve: cveLinks, mitre: mitreLinks, crypto: noLinks, mac: noLinks
    };
    const sections = [];
    for (const key of Object.keys(labelMap)) {
      const values = grouped[key] || [];
      if (!values.length) continue;
      const rows = values.map(v => `| \`${v}\` | ${linkMap[key](v)} |`).join('\n');
      sections.push(`**${labelMap[key]}**\n| Indicator | Links |\n|-----------|-------|\n${rows}\n`);
    }
    return sections.join('\n');
  }

  function buildTriagePrompt(iocs, rawInput, template) {
    const grouped = {};
    for (const i of iocs) {
      const key = i.category in { ip:1, domain:1, url:1, hostname:1, hash:1, email:1, cve:1, mitre:1, crypto:1, mac:1 } ? i.category : 'hostname';
      (grouped[key] = grouped[key] || []).push(i.value);
    }
    const table = buildDefaultIocTable(grouped);
    const fmtIocs = iocs.map(i => `[${i.category}]: ${i.value}`).join('\n');
    const contextSection = rawInput && rawInput.length < 2000
      ? `\n\nAlert/Context Text Provided:\n\"\"\"\n${rawInput}\n\"\"\"`
      : '';

    if (!template) {
      return `You are a seasoned SOC analyst tasked with producing a concise, clear, and actionable triage report for a security alert. Use the IOCs and alert context below to complete each section of the report.${contextSection}

Pre-extracted IOCs (use these to populate Section 6):
${table}

---

Produce a triage report using **exactly** the following structure and markdown formatting:

# Security Alert Triage Report

## 1. Priority and Severity
State the alert priority (Critical / High / Medium / Low) clearly, with a one-sentence justification.

---

## 2. What Was Observed
- **Alert Source & Name:**
- **Affected Host(s) & IP(s):**
- **Suspicious Activity / Indicators Detected:**
- **Relevant Time Window:**
- **Detection Logic Summary:**

---

## 3. What Is the Risk
- **True Positive or False Positive:**
- **Potential Impact:**
- **Attacker Behaviour Context:**

---

## 4. Threat Context
- **Vulnerability / Malware Details:**
- **Attacker TTPs (with [MITRE ATT&CK](https://attack.mitre.org) links where applicable):**
- **Relevant Threat Intelligence:**

---

## 5. What Is Recommended
- **Immediate Actions:**
- **Longer-Term Remediation:**
- **Monitoring / Hunting Follow-Up:**

---

## 6. Extracted IOCs
Use the pre-extracted IOC tables provided above. Preserve the VirusTotal, AbuseIPDB, NVD, and ATT&CK links. If a section has no indicators, omit it.

---

Formatting rules:
- Use markdown headings and \`---\` horizontal rules between sections.
- Use tables with clickable links for IOC listings.
- Keep language professional, clear, and concise — suitable for both technical teams and management.
- When referencing CVEs, MITRE techniques, or tools, include official links.
- Avoid unexplained technical jargon.`;
    }

    let out = template;
    if (out.includes('{{iocs}}')) {
      out = out.split('{{iocs}}').join(fmtIocs);
    } else {
      out += '\n\n## Indicators\n\n' + fmtIocs;
    }
    if (out.includes('{{rawInput}}')) {
      out = out.split('{{rawInput}}').join(rawInput || '');
    } else if (rawInput) {
      out += '\n\n## Raw input\n\n' + rawInput;
    }
    return out;
  }

  return { buildDefaultIocTable, buildTriagePrompt };
});
