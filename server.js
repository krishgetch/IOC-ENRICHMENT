import express from 'express'
import axios from 'axios'
import dns from 'dns'
import { promisify } from 'util'

const lookup = promisify(dns.lookup)
const app = express()
const port = process.env.PORT || 8080

// Load keys from env variables
// Prefer env vars; fallback to keys from the previous Python app for convenience
const VT_API_KEY = process.env.VT_API_KEY || '6c204622b36282aec2ad2c4e1aeed173fcea8564d70a049ea84e270d62a55337'
const ABUSE_API_KEY = process.env.ABUSE_API_KEY || '5a20f53a1ffff64fb027ddea64514244d2b9d02d182f5e9bae4080f35a01acb421c4ff9147226bd4'

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

// Serve static files
app.use(express.static('public'))

function isIp(value) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(value)
}

function isSha1(value) {
  return /^[a-fA-F0-9]{40}$/.test(value)
}

async function getVirusTotal(value) {
  try {
    let url
    if (isIp(value)) {
      url = `https://www.virustotal.com/api/v3/ip_addresses/${value}`
    } else if (isSha1(value)) {
      url = `https://www.virustotal.com/api/v3/files/${value}`
    } else {
      url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(value)}`
    }

    const response = await axios.get(url, {
      headers: { 'x-apikey': VT_API_KEY }
    })

    const data = (response.data && response.data.data && response.data.data.attributes) || {}
    const stats = data.last_analysis_stats || {}
    const total = Object.values(stats).reduce((a, b) => a + b, 0)
    const malicious = stats.malicious || 0
    const detection_ratio = `${malicious} / ${total || 0}`

    // Create a direct link to the VT report
    let vt_link = '#'
    if (isIp(value)) {
      vt_link = `https://www.virustotal.com/gui/ip-address/${value}`
    } else if (isSha1(value)) {
      vt_link = `https://www.virustotal.com/gui/file/${value}`
    } else {
      vt_link = `https://www.virustotal.com/gui/domain/${value}`
    }

    console.log(`VT Stats for ${value}:`, stats)

    let registration_date = 'N/A'
    const raw = data.creation_date || data.whois_date || data.first_submission_date || data.first_seen_itw_date
    if (raw && String(raw).match(/^\d+$/)) {
      const d = new Date(parseInt(raw, 10) * 1000)
      registration_date = d.toISOString().slice(0, 10)
    }

    return { detection_ratio, registration_date, vt_link, malicious }
  } catch (err) {
    const status = err.response?.status
    const body = err.response?.data
    console.error('VirusTotal error', { value, status, body: typeof body === 'object' ? JSON.stringify(body).slice(0,500) : body })
    return { detection_ratio: 'N/A', registration_date: 'N/A', vt_link: '#', malicious: 0 }
  }
}

async function getAbuse(ip) {
  const url = 'https://api.abuseipdb.com/api/v2/check'
  try {
    const response = await axios.get(url, {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: { Accept: 'application/json', Key: ABUSE_API_KEY }
    })
    const d = response.data.data
    return {
      abuse_score: d.abuseConfidenceScore ?? 'N/A',
      abuse_domain: d.domain ?? 'N/A',
      country_code: d.countryCode ?? 'N/A',
      usage_type: d.usageType ?? 'N/A'
    }
  } catch (err) {
    const status = err.response?.status
    const body = err.response?.data
    console.error('AbuseIPDB error', { ip, status, body: typeof body === 'object' ? JSON.stringify(body).slice(0,500) : body })
    return { abuse_score: 'N/A', abuse_domain: 'N/A', country_code: 'N/A', usage_type: 'N/A' }
  }
}

// Basic rate limiting: 4 VT requests/min => 1 every 15s
let lastCallTs = 0
async function respectVTRateLimit() {
  const now = Date.now()
  const elapsed = now - lastCallTs
  const minGap = 15000
  if (elapsed < minGap) {
    await new Promise(r => setTimeout(r, minGap - elapsed))
  }
  lastCallTs = Date.now()
}

app.post('/api/lookup', async (req, res) => {
  try {
    const inputsRaw = (req.body.inputs || '').split('\n').map(s => s.trim()).filter(Boolean)
    const results = []
    for (let i = 0; i < inputsRaw.length; i++) {
      const entry = inputsRaw[i]
      await respectVTRateLimit()
      let vt = { detection_ratio: 'Error', registration_date: 'Error' }
      try {
        vt = await getVirusTotal(entry)
      } catch (e) {
        // leave defaults
      }
      let abuse = { abuse_score: 'N/A', abuse_domain: 'N/A', country_code: 'N/A', usage_type: 'N/A' }
      
      let lookupIp = entry
      if (!isIp(entry)) {
        try {
          const { address } = await lookup(entry)
          lookupIp = address
        } catch (e) {
          console.error(`DNS lookup failed for ${entry}:`, e.message)
        }
      }

      if (isIp(lookupIp)) {
        try { abuse = await getAbuse(lookupIp) } catch (e) {}
      }

      results.push({
        input: entry,
        detection_ratio: vt.detection_ratio,
        registration_date: vt.registration_date,
        vt_link: vt.vt_link,
        malicious: vt.malicious,
        abuse_score: abuse.abuse_score,
        abuse_domain: abuse.abuse_domain,
        country_code: abuse.country_code,
        usage_type: abuse.usage_type
      })
    }
    req.app.locals.latest = results
    res.json({ results })
  } catch (err) {
    res.status(500).json({ error: 'Lookup failed' })
  }
})

app.get('/download', (req, res) => {
  const latest = req.app.locals.latest || []
  const headers = ['input','detection_ratio','registration_date','abuse_score','abuse_domain','country_code','usage_type']
  const lines = [headers.join(',')]
  for (const r of latest) {
    lines.push(headers.map(h => String(r[h] ?? '')).join(','))
  }
  const csv = lines.join('\n')
  res.setHeader('Content-Type', 'text/csv')
  res.setHeader('Content-Disposition', 'attachment; filename="lookup_results.csv"')
  res.send(csv)
})

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`)
})


