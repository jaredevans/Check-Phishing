import './style.css'

document.querySelector('#app').innerHTML = `
  <div class="container">
    <header class="header">
      <div class="logo">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
        </svg>
      </div>
      <h1>Phishing Check</h1>
      <p class="subtitle">Paste email headers to analyze for authenticity</p>
      <p class="subtitle-note">We do not store or save anything you paste here.</p>
    </header>
    
    <main>
      <div class="input-group">
        <div class="label-row">
          <label for="phishing-input">Email Headers</label>
          <button id="help-button" class="help-button" type="button" title="How do I find email with full headers?">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" />
            </svg>
            <span>How do I find email with full headers?</span>
          </button>
        </div>
        <textarea 
          id="phishing-input" 
          placeholder="Paste the full email headers here..."
          spellcheck="false"
        ></textarea>
      </div>
      
      <div class="button-container">
        <button id="check-button" class="check-button" type="button">
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
          </svg>
          Phishing Check
        </button>
      </div>
      
      <div id="results" class="results hidden"></div>
    </main>
    
    <footer class="footer-note">
      <p>Enter email headers above and click the button to check for phishing indicators</p>
    </footer>
  </div>
  
  <!-- Help Modal -->
  <div id="help-modal" class="modal hidden">
    <div class="modal-backdrop"></div>
    <div class="modal-content">
      <button id="modal-close" class="modal-close" type="button">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
      <h2>How to "Show Original" in Gmail</h2>
      <p class="modal-subtitle">Web Version</p>
      <ol class="help-steps">
        <li>
          <span class="step-number">1</span>
          <span class="step-text">Open <strong>Gmail</strong> in your web browser.</span>
        </li>
        <li>
          <span class="step-number">2</span>
          <span class="step-text">Open the <strong>email</strong> you want to inspect.</span>
        </li>
        <li>
          <span class="step-number">3</span>
          <span class="step-text">At the top-right corner of the email (in the message itself, not the Gmail window), you'll see a <strong>three-dot menu</strong> (︙) called "More."</span>
        </li>
        <li>
          <span class="step-number">4</span>
          <span class="step-text">Click on <strong>More</strong> (︙).</span>
        </li>
        <li>
          <span class="step-number">5</span>
          <span class="step-text">In the drop-down menu, click <strong>"Show original"</strong>.</span>
        </li>
        <li>
          <span class="step-number">6</span>
          <span class="step-text">A new tab or window will open, showing the <strong>raw email text and full headers</strong>.</span>
        </li>
      </ol>
      <div class="modal-footer">
        <button id="modal-got-it" class="modal-button" type="button">Got it!</button>
      </div>
    </div>
  </div>
`

// Email header parser and validator
class EmailHeaderAnalyzer {
  constructor(rawHeaders) {
    this.rawHeaders = rawHeaders
    this.headers = {}
    this.issues = []
    this.warnings = []
    this.passed = []
  }

  parse() {
    // Unfold headers (lines starting with whitespace are continuations)
    const unfolded = this.rawHeaders.replace(/\r?\n[ \t]+/g, ' ')
    const lines = unfolded.split(/\r?\n/)

    for (const line of lines) {
      const colonIndex = line.indexOf(':')
      if (colonIndex > 0) {
        const key = line.substring(0, colonIndex).trim().toLowerCase()
        const value = line.substring(colonIndex + 1).trim()

        // Security: Prevent prototype pollution attacks
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
          continue
        }

        // Handle multiple headers with same name
        if (Object.prototype.hasOwnProperty.call(this.headers, key)) {
          if (Array.isArray(this.headers[key])) {
            this.headers[key].push(value)
          } else {
            this.headers[key] = [this.headers[key], value]
          }
        } else {
          this.headers[key] = value
        }
      }
    }
    return this
  }

  // Extract email address from header value
  extractEmail(headerValue) {
    if (!headerValue) return null
    // Handle array values (multiple headers with same name)
    const value = Array.isArray(headerValue) ? headerValue[0] : headerValue
    if (typeof value !== 'string') return null
    const match = value.match(/<([^>]+)>/) || value.match(/([^\s<>]+@[^\s<>]+)/)
    return match ? match[1].toLowerCase() : null
  }

  // Extract domain from email
  extractDomain(email) {
    if (!email) return null
    const parts = email.split('@')
    return parts.length === 2 ? parts[1].toLowerCase() : null
  }

  // Check SPF result
  checkSPF() {
    let spfHeader = this.headers['received-spf']
    const authResults = this.headers['authentication-results']

    // Handle multiple Received-SPF headers (take first one)
    if (Array.isArray(spfHeader)) {
      spfHeader = spfHeader[0]
    }

    if (spfHeader && typeof spfHeader === 'string') {
      const spfResult = spfHeader.toLowerCase()
      if (spfResult.startsWith('pass')) {
        this.passed.push({
          check: 'SPF (Sender Policy Framework)',
          detail: 'SPF check passed - the sending server is authorized to send mail for this domain',
          raw: spfHeader.substring(0, 200)
        })
        return 'pass'
      } else if (spfResult.startsWith('fail') || spfResult.startsWith('hardfail')) {
        this.issues.push({
          check: 'SPF (Sender Policy Framework)',
          detail: 'SPF check FAILED - the sending server is NOT authorized to send mail for this domain',
          severity: 'critical',
          raw: spfHeader.substring(0, 200)
        })
        return 'fail'
      } else if (spfResult.startsWith('softfail')) {
        this.warnings.push({
          check: 'SPF (Sender Policy Framework)',
          detail: 'SPF softfail - the domain owner has indicated the server should not be sending mail (but not enforced)',
          raw: spfHeader.substring(0, 200)
        })
        return 'softfail'
      } else if (spfResult.startsWith('neutral') || spfResult.startsWith('none')) {
        this.warnings.push({
          check: 'SPF (Sender Policy Framework)',
          detail: 'SPF neutral/none - no SPF policy defined for this domain',
          raw: spfHeader.substring(0, 200)
        })
        return 'neutral'
      }
    }

    // Fallback to authentication-results
    if (authResults) {
      const authStr = Array.isArray(authResults) ? authResults.join(' ') : authResults
      const spfMatch = authStr.match(/spf=(pass|fail|softfail|neutral|none)/i)
      if (spfMatch) {
        const result = spfMatch[1].toLowerCase()
        if (result === 'pass') {
          this.passed.push({
            check: 'SPF (Sender Policy Framework)',
            detail: 'SPF check passed according to Authentication-Results header',
            raw: spfMatch[0]
          })
          return 'pass'
        } else {
          this.issues.push({
            check: 'SPF (Sender Policy Framework)',
            detail: `SPF result: ${result}`,
            severity: result === 'fail' ? 'critical' : 'warning'
          })
          return result
        }
      }
    }

    this.warnings.push({
      check: 'SPF (Sender Policy Framework)',
      detail: 'No SPF results found in headers'
    })
    return 'unknown'
  }

  // Check DKIM result
  checkDKIM() {
    const authResults = this.headers['authentication-results']
    const dkimSig = this.headers['dkim-signature']

    if (authResults) {
      const authStr = Array.isArray(authResults) ? authResults.join(' ') : authResults
      const dkimMatch = authStr.match(/dkim=(pass|fail|neutral|none)(\s+[^;]*)?/i)

      if (dkimMatch) {
        const result = dkimMatch[1].toLowerCase()
        const details = dkimMatch[2] || ''

        if (result === 'pass') {
          // Extract signing domain
          const domainMatch = details.match(/header\.i=@([^\s;]+)/i) || details.match(/header\.d=([^\s;]+)/i)
          const signingDomain = domainMatch ? domainMatch[1] : 'unknown'

          this.passed.push({
            check: 'DKIM (DomainKeys Identified Mail)',
            detail: `DKIM signature verified successfully for domain: ${signingDomain}`,
            raw: dkimMatch[0]
          })
          return 'pass'
        } else {
          this.issues.push({
            check: 'DKIM (DomainKeys Identified Mail)',
            detail: `DKIM verification ${result} - the email signature could not be validated`,
            severity: 'critical'
          })
          return result
        }
      }

      // Check for permerror or temperror
      const dkimErrorMatch = authStr.match(/dkim=(permerror|temperror)(\s+[^;]*)?/i)
      if (dkimErrorMatch) {
        const errorType = dkimErrorMatch[1].toLowerCase()
        const errorDetail = dkimErrorMatch[2] || ''
        this.issues.push({
          check: 'DKIM (DomainKeys Identified Mail)',
          detail: `DKIM ${errorType} - ${errorType === 'permerror' ? 'no valid key found for signature (likely fake/invalid signature)' : 'temporary error during verification'}`,
          severity: 'critical',
          raw: dkimErrorMatch[0] + errorDetail
        })
        return errorType
      }
    }

    if (dkimSig) {
      this.warnings.push({
        check: 'DKIM (DomainKeys Identified Mail)',
        detail: 'DKIM signature present but no verification result found'
      })
      return 'unknown'
    }

    this.warnings.push({
      check: 'DKIM (DomainKeys Identified Mail)',
      detail: 'No DKIM signature found in email'
    })
    return 'none'
  }

  // Check DMARC result
  checkDMARC() {
    const authResults = this.headers['authentication-results']

    if (authResults) {
      const authStr = Array.isArray(authResults) ? authResults.join(' ') : authResults
      const dmarcMatch = authStr.match(/dmarc=(pass|fail|none|bestguesspass)(\s+[^;]*)?/i)

      if (dmarcMatch) {
        const result = dmarcMatch[1].toLowerCase()
        const details = dmarcMatch[2] || ''

        // Extract policy
        const policyMatch = details.match(/p=(NONE|QUARANTINE|REJECT)/i)
        const policy = policyMatch ? policyMatch[1] : 'unknown'

        if (result === 'pass' || result === 'bestguesspass') {
          this.passed.push({
            check: 'DMARC (Domain-based Message Authentication)',
            detail: `DMARC check passed (policy: ${policy})`,
            raw: dmarcMatch[0]
          })
          return 'pass'
        } else if (result === 'fail') {
          this.issues.push({
            check: 'DMARC (Domain-based Message Authentication)',
            detail: `DMARC check FAILED - email does not align with domain's authentication policy (policy: ${policy})`,
            severity: policy.toLowerCase() === 'reject' ? 'critical' : 'warning'
          })
          return 'fail'
        }
      }
    }

    this.warnings.push({
      check: 'DMARC (Domain-based Message Authentication)',
      detail: 'No DMARC results found in headers'
    })
    return 'unknown'
  }

  // Check sender alignment (From, Reply-To, Return-Path)
  checkSenderAlignment() {
    const from = this.extractEmail(this.headers['from'])
    const replyTo = this.extractEmail(this.headers['reply-to'])
    const returnPath = this.extractEmail(this.headers['return-path'])

    const fromDomain = this.extractDomain(from)
    const replyToDomain = this.extractDomain(replyTo)
    const returnPathDomain = this.extractDomain(returnPath)

    let aligned = true

    // Check Reply-To alignment
    if (replyTo && from && replyTo !== from) {
      if (replyToDomain !== fromDomain) {
        this.issues.push({
          check: 'Reply-To Alignment',
          detail: `Reply-To domain (${replyToDomain}) differs from From domain (${fromDomain}) - replies may go to a different domain`,
          severity: 'warning'
        })
        aligned = false
      } else {
        this.passed.push({
          check: 'Reply-To Alignment',
          detail: `Reply-To (${replyTo}) is in the same domain as From (${from})`
        })
      }
    } else if (replyTo && replyTo === from) {
      this.passed.push({
        check: 'Reply-To Alignment',
        detail: `Reply-To matches From address exactly`
      })
    }

    // Check Return-Path alignment
    if (returnPath && from) {
      if (returnPathDomain === fromDomain) {
        this.passed.push({
          check: 'Return-Path Alignment',
          detail: `Return-Path domain (${returnPathDomain}) matches From domain (${fromDomain})`
        })
      } else {
        this.warnings.push({
          check: 'Return-Path Alignment',
          detail: `Return-Path domain (${returnPathDomain}) differs from From domain (${fromDomain})`
        })
      }
    }

    // Check Delivered-To vs To mismatch (indicates BCC/mass mailing)
    const deliveredTo = this.extractEmail(this.headers['delivered-to'])
    const to = this.extractEmail(this.headers['to'])

    if (deliveredTo && to && deliveredTo !== to) {
      const deliveredToDomain = this.extractDomain(deliveredTo)
      const toDomain = this.extractDomain(to)

      // Check if domains are also different (stronger indicator)
      if (deliveredToDomain !== toDomain) {
        this.issues.push({
          check: 'Recipient Mismatch',
          detail: `Email was sent to "${to}" but delivered to "${deliveredTo}" - this suggests BCC mass mailing or the sender doesn't know who you are`,
          severity: 'warning'
        })
        aligned = false
      } else {
        this.warnings.push({
          check: 'Recipient Mismatch',
          detail: `Email addressed to different user on same domain - may be forwarded or BCC'd`
        })
      }
    }

    return aligned
  }

  // Check ARC (Authenticated Received Chain) results
  checkARC() {
    const arcResults = this.headers['arc-authentication-results']

    if (arcResults) {
      const arcStr = Array.isArray(arcResults) ? arcResults.join(' ') : arcResults

      // Check if ARC shows all passing
      const spfPass = arcStr.includes('spf=pass')
      const dkimPass = arcStr.includes('dkim=pass')
      const dmarcPass = arcStr.includes('dmarc=pass')

      if (spfPass && dkimPass && dmarcPass) {
        this.passed.push({
          check: 'ARC (Authenticated Received Chain)',
          detail: 'ARC chain validates - email passed authentication at each hop'
        })
        return 'pass'
      }
    }

    return 'unknown'
  }

  // Check for suspicious header patterns
  checkSuspiciousPatterns() {
    // Get first value if array
    const fromHeader = this.headers['from']
    const from = Array.isArray(fromHeader) ? fromHeader[0] : (fromHeader || '')

    if (typeof from !== 'string') return

    // Check for display name spoofing
    const displayNameMatch = from.match(/^([^<]+)</)
    if (displayNameMatch) {
      const displayName = displayNameMatch[1].trim().toLowerCase()
      const fromEmail = this.extractEmail(from)

      // Check if display name contains an email address different from actual email
      const emailInName = displayName.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i)
      if (emailInName && emailInName[0] !== fromEmail) {
        this.issues.push({
          check: 'Display Name Spoofing',
          detail: `Display name contains different email (${emailInName[0]}) than actual sender (${fromEmail})`,
          severity: 'critical'
        })
      }
    }

    // Check for Sender vs From mismatch (common in calendar invite abuse)
    const senderHeader = this.headers['sender']
    if (senderHeader && from) {
      const senderEmail = this.extractEmail(senderHeader)
      const fromEmail = this.extractEmail(from)
      const senderDomain = this.extractDomain(senderEmail)
      const fromDomain = this.extractDomain(fromEmail)

      if (senderEmail && fromEmail && senderDomain !== fromDomain) {
        // Check for Google Calendar abuse specifically
        if (senderEmail && senderEmail.includes('calendar-notification@google.com')) {
          this.issues.push({
            check: 'Calendar Invite Abuse',
            detail: `Email sent via Google Calendar but From address is ${fromEmail} - attackers abuse calendar invites to bypass spam filters`,
            severity: 'critical'
          })
        } else {
          this.issues.push({
            check: 'Sender/From Mismatch',
            detail: `Sender header (${senderEmail}) does not match From header (${fromEmail}) - email is being sent on behalf of another address`,
            severity: 'warning'
          })
        }
      }
    }

    // Check for typosquat domains (lookalike domains for common providers)
    const fromEmail = this.extractEmail(from)
    const fromDomain = this.extractDomain(fromEmail)
    if (fromDomain) {
      const typosquatPatterns = [
        { legit: 'gmail.com', lookalikes: ['gmalil.com', 'gmial.com', 'gmai1.com', 'gmall.com', 'gmaill.com', 'gmaiI.com', 'gmalir.com', 'gmali.com', 'g-mail.com', 'grnail.com', 'gmail.co', 'gmaIl.com', 'qmail.com'] },
        { legit: 'yahoo.com', lookalikes: ['yah00.com', 'yaho.com', 'yahooo.com', 'yaho0.com', 'yaaho.com', 'yahoo.co', 'ymail.co'] },
        { legit: 'outlook.com', lookalikes: ['outl00k.com', 'out1ook.com', 'outIook.com', 'outlook.co', 'outlok.com', '0utlook.com'] },
        { legit: 'hotmail.com', lookalikes: ['h0tmail.com', 'hotmai1.com', 'hotmaiI.com', 'hotmall.com', 'hotmail.co'] },
        { legit: 'icloud.com', lookalikes: ['icl0ud.com', 'icloud.co', 'icIoud.com', 'lcloud.com', 'ic1oud.com'] },
        { legit: 'microsoft.com', lookalikes: ['micros0ft.com', 'mircosoft.com', 'microsft.com', 'mlcrosoft.com', 'microsoft.co'] },
        { legit: 'google.com', lookalikes: ['go0gle.com', 'googel.com', 'g00gle.com', 'googie.com', 'google.co'] },
        { legit: 'paypal.com', lookalikes: ['paypa1.com', 'paypaI.com', 'paypall.com', 'pay-pal.com', 'paypal.co'] },
        { legit: 'bestbuy.com', lookalikes: ['best-buy.com', 'bestbuy.co', 'bestbu.com', 'besttbuy.com'] },
      ]

      for (const { legit, lookalikes } of typosquatPatterns) {
        if (lookalikes.includes(fromDomain)) {
          this.issues.push({
            check: 'Typosquat Domain',
            detail: `Domain "${fromDomain}" appears to impersonate "${legit}" using lookalike characters`,
            severity: 'critical'
          })
          break
        }
        // Also check for similar patterns dynamically (single char substitution)
        if (fromDomain !== legit && this.isSimilarDomain(fromDomain, legit)) {
          this.issues.push({
            check: 'Typosquat Domain',
            detail: `Domain "${fromDomain}" is suspiciously similar to "${legit}" - possible typosquatting`,
            severity: 'critical'
          })
          break
        }
      }
    }

    // Check for Google infrastructure usage (common for legitimate Gmail/Workspace emails)
    const receivedHeaders = this.headers['received']
    if (receivedHeaders) {
      const receivedArr = Array.isArray(receivedHeaders) ? receivedHeaders : [receivedHeaders]
      const fromGoogle = receivedArr.some(r => typeof r === 'string' && (r.includes('google.com') || r.includes('1e100.net')))
      if (fromGoogle) {
        this.passed.push({
          check: 'Mail Server Origin',
          detail: 'Email routed through Google mail infrastructure'
        })
      }
    }
  }

  // Check if two domains are suspiciously similar (Levenshtein distance <= 2)
  isSimilarDomain(domain1, domain2) {
    if (Math.abs(domain1.length - domain2.length) > 2) return false

    // Simple Levenshtein distance check
    const len1 = domain1.length
    const len2 = domain2.length
    const matrix = []

    for (let i = 0; i <= len1; i++) {
      matrix[i] = [i]
    }
    for (let j = 0; j <= len2; j++) {
      matrix[0][j] = j
    }

    for (let i = 1; i <= len1; i++) {
      for (let j = 1; j <= len2; j++) {
        const cost = domain1[i - 1] === domain2[j - 1] ? 0 : 1
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        )
      }
    }

    return matrix[len1][len2] <= 2 && matrix[len1][len2] > 0
  }

  // Helper to get first value if array
  getHeaderValue(key) {
    const value = this.headers[key]
    if (!value) return null
    return Array.isArray(value) ? value[0] : value
  }

  // Get sender info for display
  getSenderInfo() {
    return {
      from: this.getHeaderValue('from') || 'Unknown',
      to: this.getHeaderValue('to') || 'Unknown',
      subject: this.getHeaderValue('subject') || 'No Subject',
      date: this.getHeaderValue('date') || 'Unknown',
      replyTo: this.getHeaderValue('reply-to') || null,
      returnPath: this.getHeaderValue('return-path') || null
    }
  }

  analyze() {
    this.parse()

    // Run all checks
    this.checkSPF()
    this.checkDKIM()
    this.checkDMARC()
    this.checkARC()
    this.checkSenderAlignment()
    this.checkSuspiciousPatterns()

    const senderInfo = this.getSenderInfo()

    return {
      senderInfo,
      passed: this.passed,
      warnings: this.warnings,
      issues: this.issues,
      isValid: this.issues.filter(i => i.severity === 'critical').length === 0
    }
  }
}

// Email Body Content Analyzer
class EmailBodyAnalyzer {
  constructor(rawEmail) {
    this.rawEmail = rawEmail
    this.body = this.extractBody(rawEmail)
    this.score = 0
    this.findings = []
  }

  extractBody(rawEmail) {
    // Try to extract body after double newline (header/body separator)
    const parts = rawEmail.split(/\r?\n\r?\n/)
    if (parts.length > 1) {
      // Join everything after headers
      let body = parts.slice(1).join('\n\n')

      // Try to decode base64 content if present
      body = this.decodeBase64Content(body)

      return body
    }
    // If no clear separator, analyze the whole thing
    return rawEmail
  }

  // Decode base64 encoded content blocks
  decodeBase64Content(text) {
    let result = text

    // Method 1: Look for MIME base64 blocks (multi-line base64 with newlines)
    // Base64 in MIME is typically wrapped at 76 characters
    const mimeBase64Pattern = /(?:^|\n)((?:[A-Za-z0-9+/]{4,76}\r?\n?)+[A-Za-z0-9+/]*={0,2})/gm
    const mimeMatches = text.match(mimeBase64Pattern)

    if (mimeMatches) {
      for (const match of mimeMatches) {
        // Remove all whitespace to get continuous base64
        const cleanedBase64 = match.replace(/[\s\r\n]/g, '')
        // Only try to decode if it's long enough to be meaningful content
        if (cleanedBase64.length >= 100) {
          try {
            const decoded = atob(cleanedBase64)
            // Only use if it looks like HTML or text (has tags or printable chars)
            if (decoded && (decoded.includes('<') || /^[\x09\x0A\x0D\x20-\x7E]{20,}/.test(decoded.substring(0, 100)))) {
              result += '\n\n[DECODED BASE64 CONTENT]\n' + decoded
            }
          } catch (e) {
            // Not valid base64, ignore
          }
        }
      }
    }

    // Method 2: Also look for continuous base64 strings (no line breaks)
    const continuousBase64Pattern = /([A-Za-z0-9+/]{100,}={0,2})/g
    const contMatches = text.match(continuousBase64Pattern)
    if (contMatches) {
      for (const match of contMatches) {
        try {
          const decoded = atob(match)
          if (decoded && (decoded.includes('<') || /^[\x09\x0A\x0D\x20-\x7E]{20,}/.test(decoded.substring(0, 100)))) {
            // Avoid duplicates
            if (!result.includes(decoded.substring(0, 50))) {
              result += '\n\n[DECODED BASE64 CONTENT]\n' + decoded
            }
          }
        } catch (e) {
          // Not valid base64, ignore
        }
      }
    }

    return result
  }

  // Decode quoted-printable content
  decodeQuotedPrintable(text) {
    return text
      .replace(/=\r?\n/g, '') // Remove soft line breaks
      .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
  }

  getCleanText() {
    let text = this.body
    // Decode quoted-printable
    text = this.decodeQuotedPrintable(text)
    // Remove HTML tags
    text = text.replace(/<[^>]+>/g, ' ')
    // Remove MIME boundaries
    text = text.replace(/--[a-zA-Z0-9_=]+/g, '')
    // Normalize whitespace
    text = text.replace(/\s+/g, ' ').trim()
    return text.toLowerCase()
  }

  addFinding(category, description, points, matches = []) {
    this.score += points
    this.findings.push({
      category,
      description,
      points,
      matches: matches.slice(0, 5) // Limit to 5 examples
    })
  }

  // Check for urgency language
  checkUrgency() {
    const urgencyPatterns = [
      { pattern: /\burgent\b/gi, points: 5 },
      { pattern: /\bimmediately\b/gi, points: 5 },
      { pattern: /\bact now\b/gi, points: 8 },
      { pattern: /\bright away\b/gi, points: 5 },
      { pattern: /\basap\b/gi, points: 4 },
      { pattern: /\bexpir(e|es|ed|ing)\b/gi, points: 4 },
      { pattern: /\btime.{0,10}sensitive\b/gi, points: 6 },
      { pattern: /\bwithin\s+\d+\s+(hours?|days?)\b/gi, points: 6 },
      { pattern: /\b(24|48|72)\s*hours?\b/gi, points: 5 },
      { pattern: /\blimited time\b/gi, points: 5 },
      { pattern: /\bdon'?t delay\b/gi, points: 5 },
      { pattern: /\brespond immediately\b/gi, points: 7 },
    ]

    const text = this.getCleanText()
    let totalPoints = 0
    const matches = []

    for (const { pattern, points } of urgencyPatterns) {
      const found = text.match(pattern)
      if (found) {
        totalPoints += points * Math.min(found.length, 2) // Cap at 2 occurrences
        matches.push(...found)
      }
    }

    if (totalPoints > 0) {
      this.addFinding(
        'Urgency Language',
        'Message contains urgent/time-pressure language commonly used in phishing',
        Math.min(totalPoints, 20),
        matches
      )
    }
  }

  // Check for threat language
  checkThreats() {
    const threatPatterns = [
      { pattern: /\bsuspend(ed)?\b/gi, points: 6 },
      { pattern: /\bterminat(e|ed|ion)\b/gi, points: 6 },
      { pattern: /\bcompromised\b/gi, points: 7 },
      { pattern: /\blocked\b/gi, points: 5 },
      { pattern: /\brestricted\b/gi, points: 4 },
      { pattern: /\bunauthorized\b/gi, points: 5 },
      { pattern: /\bsuspicious activity\b/gi, points: 8 },
      { pattern: /\bfraudulent\b/gi, points: 6 },
      { pattern: /\bbreach\b/gi, points: 5 },
      { pattern: /\bviolation\b/gi, points: 4 },
      { pattern: /\blegal action\b/gi, points: 7 },
      { pattern: /\bcourt\b/gi, points: 4 },
      { pattern: /\barrest\b/gi, points: 6 },
      { pattern: /\bwarrant\b/gi, points: 5 },
      { pattern: /\bpermanently\s+(delete|remove|close)\b/gi, points: 7 },
    ]

    const text = this.getCleanText()
    let totalPoints = 0
    const matches = []

    for (const { pattern, points } of threatPatterns) {
      const found = text.match(pattern)
      if (found) {
        totalPoints += points * Math.min(found.length, 2)
        matches.push(...found)
      }
    }

    if (totalPoints > 0) {
      this.addFinding(
        'Threat/Fear Language',
        'Message contains threatening language designed to create fear',
        Math.min(totalPoints, 25),
        matches
      )
    }
  }

  // Check for requests for sensitive information
  checkSensitiveInfoRequests() {
    const sensitivePatterns = [
      { pattern: /\bpassword\b/gi, points: 6 },
      { pattern: /\bcredit card\b/gi, points: 8 },
      { pattern: /\bssn\b|\bsocial security\b/gi, points: 10 },
      { pattern: /\bbank account\b/gi, points: 7 },
      { pattern: /\brouting number\b/gi, points: 8 },
      { pattern: /\bpin\b/gi, points: 5 },
      { pattern: /\bcvv\b|\bsecurity code\b/gi, points: 8 },
      { pattern: /\bdate of birth\b|\bdob\b/gi, points: 5 },
      { pattern: /\bmother'?s maiden\b/gi, points: 7 },
      { pattern: /\bverify your (identity|account|information)\b/gi, points: 8 },
      { pattern: /\bconfirm your (details|information|identity)\b/gi, points: 7 },
      { pattern: /\bupdate your (payment|billing|account)\b/gi, points: 6 },
      { pattern: /\blog\s*in credentials\b/gi, points: 7 },
    ]

    const text = this.getCleanText()
    let totalPoints = 0
    const matches = []

    for (const { pattern, points } of sensitivePatterns) {
      const found = text.match(pattern)
      if (found) {
        totalPoints += points * Math.min(found.length, 2)
        matches.push(...found)
      }
    }

    if (totalPoints > 0) {
      this.addFinding(
        'Sensitive Information Requests',
        'Message requests personal or financial information',
        Math.min(totalPoints, 25),
        matches
      )
    }
  }

  // Check for suspicious URLs
  checkSuspiciousURLs() {
    const urlPatterns = [
      // URLs with IP addresses
      { pattern: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi, points: 15, desc: 'IP address URL' },
      // URL shorteners
      { pattern: /https?:\/\/(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|j\.mp|rb\.gy)/gi, points: 8, desc: 'URL shortener' },
      // Suspicious TLDs
      { pattern: /https?:\/\/[^\s]+\.(ru|cn|tk|ml|ga|cf|top|xyz|pw|cc|ws|ua|su|biz|info|click|download|win)\/\S*/gi, points: 8, desc: 'Suspicious TLD' },
      // Lookalike domains (common brand + suspicious suffix)
      { pattern: /https?:\/\/[^\s]*(paypal|amazon|apple|microsoft|google|facebook|netflix|bank)[^\s]*\.(ru|cn|tk|info|xyz|top)/gi, points: 15, desc: 'Lookalike domain' },
      // Encoded URLs
      { pattern: /%[0-9A-Fa-f]{2}.*%[0-9A-Fa-f]{2}.*https?/gi, points: 8, desc: 'Encoded URL' },
      // Data URIs
      { pattern: /data:text\/html/gi, points: 12, desc: 'Data URI' },
      // Cloud storage abuse (commonly used to host phishing pages)
      { pattern: /https?:\/\/(storage\.googleapis\.com|firebasestorage\.googleapis\.com|.*\.web\.app|.*\.firebaseapp\.com)\/[^\s]+\.html/gi, points: 15, desc: 'Cloud storage hosting phishing page' },
      // Suspicious file hosting services used for phishing
      { pattern: /https?:\/\/(docs\.google\.com\/forms|forms\.gle)\//gi, points: 6, desc: 'Google Forms (potential credential harvesting)' },
    ]

    const text = this.body // Check raw body for URLs
    let totalPoints = 0
    const matches = []

    for (const { pattern, points, desc } of urlPatterns) {
      const found = text.match(pattern)
      if (found) {
        totalPoints += points
        matches.push(`${desc}: ${found[0].substring(0, 50)}...`)
      }
    }

    // Check for mismatched link text
    const linkMismatch = text.match(/<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)</gi)
    if (linkMismatch) {
      for (const match of linkMismatch.slice(0, 3)) {
        const href = match.match(/href=["']([^"']+)["']/i)
        const linkText = match.match(/>([^<]+)</i)
        if (href && linkText) {
          const hrefDomain = href[1].match(/https?:\/\/([^\/]+)/i)
          const textDomain = linkText[1].match(/([a-z0-9-]+\.[a-z]{2,})/i)
          if (hrefDomain && textDomain && !hrefDomain[1].includes(textDomain[1])) {
            totalPoints += 12
            matches.push(`Link text "${linkText[1]}" goes to different domain`)
          }
        }
      }
    }

    if (totalPoints > 0) {
      this.addFinding(
        'Suspicious URLs',
        'Message contains suspicious or deceptive links',
        Math.min(totalPoints, 30),
        matches
      )
    }
  }

  // Check for generic/impersonal greetings
  checkGenericGreetings() {
    const genericPatterns = [
      { pattern: /\bdear (customer|user|member|client|valued customer|sir|madam|account holder)\b/gi, points: 5 },
      { pattern: /\bhello (customer|user|member)\b/gi, points: 4 },
      { pattern: /\bdear sir\/?madam\b/gi, points: 4 },
      { pattern: /\bto whom it may concern\b/gi, points: 3 },
      { pattern: /\battention\s*:\s*(customer|user|member)/gi, points: 5 },
    ]

    const text = this.getCleanText()
    let totalPoints = 0
    const matches = []

    for (const { pattern, points } of genericPatterns) {
      const found = text.match(pattern)
      if (found) {
        totalPoints += points
        matches.push(...found)
      }
    }

    if (totalPoints > 0) {
      this.addFinding(
        'Generic Greeting',
        'Message uses impersonal greeting (legitimate senders usually know your name)',
        Math.min(totalPoints, 10),
        matches
      )
    }
  }

  // Check for "too good to be true" offers
  checkTooGoodToBeTrue() {
    const patterns = [
      { pattern: /\b(won|winner|winning|congratulations)\b/gi, points: 6 },
      { pattern: /\blottery\b/gi, points: 10 },
      { pattern: /\bprize\b/gi, points: 5 },
      { pattern: /\binheritance\b/gi, points: 10 },
      { pattern: /\bmillion (dollars|pounds|euros)\b/gi, points: 12 },
      { pattern: /\bfree (gift|money|iphone|laptop)\b/gi, points: 8 },
      { pattern: /\bunclaimed (funds|money)\b/gi, points: 10 },
      { pattern: /\bexclusive offer\b/gi, points: 4 },
      { pattern: /\bguaranteed\b/gi, points: 3 },
      { pattern: /\brisk.?free\b/gi, points: 4 },
      { pattern: /\b100%\s*(free|guaranteed|safe)\b/gi, points: 5 },
      // Casino/gambling patterns
      { pattern: /\bcasino\b/gi, points: 10 },
      { pattern: /\bfree spins?\b/gi, points: 8 },
      { pattern: /\bjackpot\b/gi, points: 8 },
      { pattern: /\bbonus\s*(code|offer|payout)?\b/gi, points: 5 },
      { pattern: /\bpayout\b/gi, points: 6 },
      { pattern: /\bno.?deposit.?(required|bonus)?\b/gi, points: 10 },
      { pattern: /\bwelcome bonus\b/gi, points: 7 },
      { pattern: /\$\d{4,}/g, points: 8 }, // Large dollar amounts like $1396
    ]

    const text = this.getCleanText()
    let totalPoints = 0
    const matches = []

    for (const { pattern, points } of patterns) {
      const found = text.match(pattern)
      if (found) {
        totalPoints += points
        matches.push(...found)
      }
    }

    if (totalPoints > 0) {
      this.addFinding(
        'Too Good To Be True',
        'Message contains offers that seem unrealistic',
        Math.min(totalPoints, 25),
        matches
      )
    }
  }

  // Check for action demands
  checkActionDemands() {
    const patterns = [
      { pattern: /\bclick (here|below|this link|the link|now)\b/gi, points: 5 },
      { pattern: /\bdownload\s+(the\s+)?(attachment|file)\b/gi, points: 6 },
      { pattern: /\bopen\s+(the\s+)?(attachment|file)\b/gi, points: 6 },
      { pattern: /\bcall (this number|now|immediately)\b/gi, points: 5 },
      { pattern: /\breply (with|to this email)\b/gi, points: 3 },
      { pattern: /\bsign in\b|\blog in\b/gi, points: 3 },
      { pattern: /\bclick.{0,20}(verify|confirm|update|secure)\b/gi, points: 7 },
    ]

    const text = this.getCleanText()
    let totalPoints = 0
    const matches = []

    for (const { pattern, points } of patterns) {
      const found = text.match(pattern)
      if (found) {
        totalPoints += points
        matches.push(...found)
      }
    }

    if (totalPoints > 0) {
      this.addFinding(
        'Action Demands',
        'Message aggressively pushes you to take immediate action',
        Math.min(totalPoints, 15),
        matches
      )
    }
  }

  // Check for poor grammar/spelling (basic checks)
  checkGrammarIssues() {
    const patterns = [
      { pattern: /\byour account have been\b/gi, points: 5 },
      { pattern: /\bhas been temporary\b/gi, points: 4 },
      { pattern: /\bkindly\b/gi, points: 3 }, // Common in scam emails
      { pattern: /\bdo the needful\b/gi, points: 5 },
      { pattern: /\brevert back\b/gi, points: 3 },
      { pattern: /\bpls\b|\bplz\b/gi, points: 2 },
      { pattern: /\bu r\b|\bur\b/gi, points: 3 },
      { pattern: /!!!+/g, points: 4 },
      { pattern: /\?\?\?+/g, points: 3 },
      { pattern: /ALL CAPS SENTENCE/g, points: 0 }, // Handled separately
    ]

    const text = this.getCleanText()
    let totalPoints = 0
    const matches = []

    for (const { pattern, points } of patterns) {
      const found = text.match(pattern)
      if (found) {
        totalPoints += points
        matches.push(...found)
      }
    }

    // Check for excessive caps (more than 20% of text)
    const capsRatio = (this.body.match(/[A-Z]/g) || []).length / this.body.length
    if (capsRatio > 0.3) {
      totalPoints += 5
      matches.push('Excessive use of capital letters')
    }

    if (totalPoints > 0) {
      this.addFinding(
        'Grammar/Style Issues',
        'Message contains unusual grammar or formatting typical of scam emails',
        Math.min(totalPoints, 15),
        matches
      )
    }
  }

  // Analyze and return results
  analyze() {
    this.checkUrgency()
    this.checkThreats()
    this.checkSensitiveInfoRequests()
    this.checkSuspiciousURLs()
    this.checkGenericGreetings()
    this.checkTooGoodToBeTrue()
    this.checkActionDemands()
    this.checkGrammarIssues()
    this.checkObfuscation()
    this.checkSubjectLine()
    this.checkRandomFromAddress()
    this.checkRecipientLocalInFrom()
    this.checkBrandImpersonation()
    this.checkTechSupportScam()

    // Determine risk level
    let riskLevel, riskDescription
    if (this.score <= 15) {
      riskLevel = 'low'
      riskDescription = 'Low Risk - Message appears normal'
    } else if (this.score <= 40) {
      riskLevel = 'medium'
      riskDescription = 'Unsure - Some suspicious patterns detected'
    } else {
      riskLevel = 'high'
      riskDescription = 'High Risk - Multiple phishing indicators detected'
    }

    return {
      score: this.score,
      riskLevel,
      riskDescription,
      findings: this.findings
    }
  }

  // Check for tech support scam patterns (phone number + billing/subscription context)
  checkTechSupportScam() {
    const text = this.getCleanText()
    const body = this.body
    let totalPoints = 0
    const matches = []

    // Look for phone numbers (US format primarily, as most scams target US)
    const phonePatterns = [
      /\+1[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/gi,  // +1-(859)-204-5293 format
      /\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/gi,            // (859) 204-5293 or 859-204-5293
      /1[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}/gi,          // 1-859-204-5293
    ]

    let hasPhoneNumber = false
    for (const pattern of phonePatterns) {
      if (pattern.test(body)) {
        hasPhoneNumber = true
        break
      }
    }

    if (hasPhoneNumber) {
      // Check for tech support scam context keywords
      const scamContextPatterns = [
        { pattern: /membership|subscription|renewal|auto.?renew/gi, points: 8 },
        { pattern: /\$\d{2,3}\.\d{2}/g, points: 10 },  // Dollar amounts like $444.33
        { pattern: /call.{0,20}(support|team|line|number|us)/gi, points: 8 },
        { pattern: /contact.{0,20}(support|our team|us)/gi, points: 6 },
        { pattern: /verification.{0,10}(notice|code|required)/gi, points: 8 },
        { pattern: /transaction.{0,10}(id|record|number|no\.?)/gi, points: 8 },
        { pattern: /reference.{0,10}(id|number|no\.?|code)/gi, points: 6 },
        { pattern: /license.{0,10}key/gi, points: 8 },
        { pattern: /support.{0,10}(line|team|outreach)/gi, points: 6 },
        { pattern: /cancel|refund|dispute/gi, points: 5 },
        { pattern: /supervising.{0,10}manager/gi, points: 10 },  // Classic scam element
        { pattern: /emergency.{0,10}(contact|line)/gi, points: 8 },
        { pattern: /corporate.{0,10}(operations|headquarters)/gi, points: 6 },
      ]

      for (const { pattern, points } of scamContextPatterns) {
        const found = text.match(pattern)
        if (found) {
          totalPoints += points
          matches.push(...found.slice(0, 2))
        }
      }

      // Extra points if phone number + billing amount combo
      if (totalPoints > 0) {
        totalPoints += 10  // Base points for having phone number in suspicious context
        matches.push('Phone number in suspicious billing/support context')
      }
    }

    if (totalPoints > 0) {
      this.addFinding(
        'Tech Support Scam Pattern',
        'Message contains phone numbers with fake billing/subscription context - classic phone scam',
        Math.min(totalPoints, 40),
        matches
      )
    }
  }

  // Check for text obfuscation techniques
  checkObfuscation() {
    const body = this.body
    let totalPoints = 0
    const matches = []

    // Check for span-per-character obfuscation (very common in phishing)
    // Pattern: <span>X</span><span>Y</span>... where X and Y are single characters
    const spanPerChar = body.match(/<span>[^<]{1,2}<\/span>\s*<span>[^<]{1,2}<\/span>/gi)
    if (spanPerChar && spanPerChar.length > 10) {
      totalPoints += 25
      matches.push(`Character-by-character span wrapping detected (${spanPerChar.length} instances)`)
    }

    // Check for zero-width characters (invisible text)
    const zeroWidth = body.match(/[\u200B\u200C\u200D\uFEFF]/g)
    if (zeroWidth && zeroWidth.length > 5) {
      totalPoints += 15
      matches.push(`Hidden zero-width characters (${zeroWidth.length} found)`)
    }

    // Check for HTML entity obfuscation
    const htmlEntities = body.match(/&#\d+;/g)
    if (htmlEntities && htmlEntities.length > 20) {
      totalPoints += 10
      matches.push(`Excessive HTML entity encoding (${htmlEntities.length} entities)`)
    }

    // Check for base64 encoded content
    if (body.match(/base64,[\w+/=]{50,}/gi)) {
      totalPoints += 12
      matches.push('Base64 encoded content detected')
    }

    if (totalPoints > 0) {
      this.addFinding(
        'Text Obfuscation',
        'Message uses techniques to hide text from detection systems',
        Math.min(totalPoints, 30),
        matches
      )
    }
  }

  // Check subject line for phishing indicators
  checkSubjectLine() {
    // Extract subject from headers portion
    const subjectMatch = this.rawEmail.match(/^Subject:\s*(.+?)(?:\r?\n(?!\s)|\r?\n\r?\n)/ims)
    if (!subjectMatch) return

    const subjectRaw = subjectMatch[1]
    const subject = subjectRaw.toLowerCase()
    let totalPoints = 0
    const matches = []

    // Check for Unicode obfuscation (math bold, fullwidth, etc.)
    // Unicode math bold: 𝗔-𝗭 (U+1D5D4 to U+1D5ED), 𝗮-𝘇 (U+1D5EE to U+1D607)
    // Fullwidth characters: Ａ-Ｚ (U+FF21 to U+FF3A)
    const unicodeTrickChars = subjectRaw.match(/[\u{1D400}-\u{1D7FF}\uFF01-\uFF5E]/gu)
    if (unicodeTrickChars && unicodeTrickChars.length > 3) {
      totalPoints += 20
      matches.push(`Unicode character substitution (${unicodeTrickChars.length} special chars)`)
    }

    // Check for money amounts in subject
    const moneyPattern = /\$\s*[\d,]+\.?\d*|\💲\s*\d+/
    if (moneyPattern.test(subjectRaw)) {
      totalPoints += 10
      matches.push('Money amount in subject')
    }

    // Check for gambling/casino keywords in subject
    if (/casino|deposit|bonus|spins|payout|jackpot|betting/i.test(subject)) {
      totalPoints += 12
      matches.push('Gambling/casino terms')
    }

    const subjectPatterns = [
      { pattern: /blocked/i, points: 8, text: 'blocked' },
      { pattern: /suspended/i, points: 8, text: 'suspended' },
      { pattern: /deleted/i, points: 7, text: 'deleted' },
      { pattern: /urgent/i, points: 6, text: 'urgent' },
      { pattern: /expired?/i, points: 5, text: 'expired' },
      { pattern: /verify|verification/i, points: 5, text: 'verify' },
      { pattern: /action required/i, points: 7, text: 'action required' },
      { pattern: /account.{0,10}(risk|danger|warning)/i, points: 8, text: 'account risk' },
      { pattern: /payment.{0,10}(fail|declin|reject)/i, points: 8, text: 'payment failed' },
      { pattern: /confirm.{0,10}identity/i, points: 7, text: 'confirm identity' },
      { pattern: /unusual.{0,10}activity/i, points: 7, text: 'unusual activity' },
      { pattern: /renew.{0,10}(now|free|subscription)/i, points: 6, text: 'renew now' },
      { pattern: /🚫|⚠️|🔴|❌|‼️|💲/u, points: 5, text: 'warning/money emojis' },
      { pattern: /no.?deposit.?required/i, points: 10, text: 'no deposit required' },
      { pattern: /you.{0,5}(won|received|have).{0,15}(deposit|\$|money)/i, points: 12, text: 'you received money' },
    ]

    for (const { pattern, points, text } of subjectPatterns) {
      if (pattern.test(subject) || pattern.test(subjectRaw)) {
        totalPoints += points
        matches.push(text)
      }
    }

    if (totalPoints > 0) {
      this.addFinding(
        'Suspicious Subject Line',
        'Email subject contains phishing trigger words or obfuscation',
        Math.min(totalPoints, 35),
        matches
      )
    }
  }

  // Check for randomized-looking From address local part
  checkRandomFromAddress() {
    const fromMatch = this.rawEmail.match(/^From:\s*(.+?)(?:\r?\n(?!\s)|\r?\n\r?\n)/im)
    if (!fromMatch) return

    const fromRaw = fromMatch[1]
    const emailMatch = fromRaw.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)
    if (!emailMatch) return

    const email = emailMatch[0]
    const localPart = email.split('@')[0] || ''
    const normalized = localPart.replace(/[^a-z0-9]/gi, '')
    if (normalized.length < 12) return

    let totalPoints = 0
    const matches = []
    const vowelCount = (normalized.match(/[aeiou]/gi) || []).length
    const vowelRatio = vowelCount / normalized.length

    if (normalized.length >= 16 && vowelRatio < 0.25) {
      totalPoints += 10
      matches.push(`Very low vowel ratio in local part (${vowelCount}/${normalized.length})`)
    }

    if (/\d{6,}/.test(localPart)) {
      totalPoints += 8
      matches.push('Long digit sequence in local part')
    }

    if (/[b-df-hj-np-tv-z]{7,}/i.test(normalized)) {
      totalPoints += 6
      matches.push('Long consonant run in local part')
    }

    if (totalPoints > 0) {
      this.addFinding(
        'Suspicious From Address',
        'From address looks auto-generated or randomized',
        Math.min(totalPoints, 20),
        matches
      )
    }
  }

  // Check if recipient local-part appears in From line
  checkRecipientLocalInFrom() {
    const toMatch = this.rawEmail.match(/^To:\s*(.+?)(?:\r?\n(?!\s)|\r?\n\r?\n)/im)
    const fromMatch = this.rawEmail.match(/^From:\s*(.+?)(?:\r?\n(?!\s)|\r?\n\r?\n)/im)
    if (!toMatch || !fromMatch) return

    const toEmailMatch = toMatch[1].match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)
    if (!toEmailMatch) return

    const toLocalPart = (toEmailMatch[0].split('@')[0] || '').toLowerCase()
    if (toLocalPart.length < 4) return

    const fromLine = fromMatch[1].toLowerCase()
    if (!fromLine.includes(toLocalPart)) return

    this.addFinding(
      'Recipient Address Reuse',
      'From line repeats recipient identifier, which is common in spoofed messages',
      8,
      [`Recipient local part found in From line: ${toLocalPart}`]
    )
  }

  // Check for brand impersonation from suspicious domains
  checkBrandImpersonation() {
    // Extract From header
    const fromMatch = this.rawEmail.match(/^From:\s*(.+?)(?:\r?\n(?!\s)|\r?\n\r?\n)/im)
    if (!fromMatch) return

    const fromHeader = fromMatch[1].toLowerCase()
    const body = this.getCleanText()

    // Known brands that are commonly impersonated
    const brands = [
      { name: 'Apple/iCloud', keywords: ['icloud', 'apple id', 'apple store', 'itunes', 'cloud photos', 'apple devices', 'iphone, ipad'], domains: ['apple.com', 'icloud.com'] },
      { name: 'Microsoft', keywords: ['microsoft', 'outlook', 'office 365', 'onedrive'], domains: ['microsoft.com', 'outlook.com', 'live.com'] },
      { name: 'Google', keywords: ['google drive', 'gmail', 'google account'], domains: ['google.com', 'gmail.com'] },
      { name: 'Amazon', keywords: ['amazon', 'prime', 'aws'], domains: ['amazon.com', 'amazon.co'] },
      { name: 'PayPal', keywords: ['paypal'], domains: ['paypal.com'] },
      { name: 'Netflix', keywords: ['netflix'], domains: ['netflix.com'] },
      { name: 'Bank', keywords: ['bank of america', 'chase bank', 'wells fargo', 'citibank'], domains: ['bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citi.com'] },
      // Tech support scam brands (commonly impersonated via phone scams)
      { name: 'GeekSquad/Best Buy', keywords: ['geeksquad', 'geek squad', 'best buy', 'bestbuy'], domains: ['geeksquad.com', 'bestbuy.com'] },
      { name: 'Norton/LifeLock', keywords: ['norton', 'lifelock', 'symantec'], domains: ['norton.com', 'lifelock.com', 'symantec.com'] },
      { name: 'McAfee', keywords: ['mcafee', 'mc afee'], domains: ['mcafee.com'] },
      { name: 'Webroot', keywords: ['webroot'], domains: ['webroot.com'] },
      // Cloud storage/subscription scams
      { name: 'iCloud/Cloud', keywords: ['cloud+', 'cloud subscription', 'cloud storage', 'device backups'], domains: ['apple.com', 'icloud.com'] },
    ]

    let totalPoints = 0
    const matches = []

    for (const brand of brands) {
      // Check if body mentions the brand
      const mentionsBrand = brand.keywords.some(kw => body.includes(kw))

      if (mentionsBrand) {
        // Check if From domain matches legitimate brand domain
        const fromLegitDomain = brand.domains.some(d => fromHeader.includes(d))

        if (!fromLegitDomain) {
          totalPoints += 20
          matches.push(`Claims to be ${brand.name} but sent from non-${brand.name} domain`)
        }
      }
    }

    // Check for suspicious domain patterns in From header
    const suspiciousDomainPatterns = [
      { pattern: /\.[a-z]{10,}\./i, desc: 'Very long subdomain' },
      { pattern: /\d{4,}/i, desc: 'Many numbers in domain' },
      { pattern: /[a-z]{15,}\./i, desc: 'Very long random string' },
      { pattern: /\.[a-z0-9]{8,}\.[a-z0-9]{8,}\.[a-z0-9]{8,}\./i, desc: 'Multiple random-looking subdomains' },
      { pattern: /\.(ua|ru|cn|tk|ml|biz)\s*$/i, desc: 'Suspicious country TLD' },
    ]

    for (const { pattern, desc } of suspiciousDomainPatterns) {
      if (pattern.test(fromHeader)) {
        totalPoints += 10
        matches.push(`From address: ${desc}`)
        break
      }
    }

    if (totalPoints > 0) {
      this.addFinding(
        'Brand Impersonation',
        'Message impersonates a known brand from an unauthorized domain',
        Math.min(totalPoints, 30),
        matches
      )
    }
  }
}

// Render results
function renderResults(results, bodyResults = null) {
  const resultsDiv = document.getElementById('results')

  const statusClass = results.isValid ? 'valid' : 'invalid'
  const statusIcon = results.isValid
    ? '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>'
    : '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" /></svg>'
  const statusText = results.isValid
    ? 'Email Headers Appear Valid'
    : 'Potential Phishing Indicators Detected'

  let html = ''

  // Body Content Analysis
  if (bodyResults) {
    const riskIcon = bodyResults.riskLevel === 'low'
      ? '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>'
      : bodyResults.riskLevel === 'medium'
        ? '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" /></svg>'
        : '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" /></svg>'

    html += `
      <div class="body-analysis">
        <h3>
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
          </svg>
          Content Analysis
        </h3>
        
        <div class="risk-indicator risk-${bodyResults.riskLevel}">
          ${riskIcon}
          <div class="risk-text">
            <span class="risk-label">${bodyResults.riskDescription}</span>
            <span class="risk-score">Phishing Score: ${bodyResults.score} points</span>
          </div>
        </div>
        
        <div class="risk-meter">
          <div class="risk-track">
            <div class="risk-fill" style="width: ${Math.min(bodyResults.score, 100)}%"></div>
          </div>
          <div class="risk-labels">
            <span>Low (0-15)</span>
            <span>Unsure (16-40)</span>
            <span>High (41+)</span>
          </div>
        </div>
    `

    if (bodyResults.findings.length > 0) {
      html += `
        <div class="findings-list">
          <h4>Findings (${bodyResults.findings.length})</h4>
          <ul>
            ${bodyResults.findings.map(finding => `
              <li class="finding-item ${finding.points >= 10 ? 'high-points' : finding.points >= 5 ? 'medium-points' : 'low-points'}">
                <div class="finding-header">
                  <strong>${escapeHtml(finding.category)}</strong>
                  <span class="finding-points">+${escapeHtml(String(finding.points))} pts</span>
                </div>
                <p>${escapeHtml(finding.description)}</p>
                ${finding.matches.length > 0 ? `
                  <div class="finding-matches">
                    ${finding.matches.map(m => `<span class="match-tag">${escapeHtml(String(m))}</span>`).join('')}
                  </div>
                ` : ''}
              </li>
            `).join('')}
          </ul>
        </div>
      `
    } else {
      html += `
        <p class="no-findings">No suspicious patterns detected in the message body.</p>
      `
    }

    html += `</div>`
  }

  html += `
    <div class="result-status ${statusClass}">
      ${statusIcon}
      <span>${statusText}</span>
    </div>
    
    <div class="sender-info">
      <h3>Email Information</h3>
      <div class="info-grid">
        <div class="info-item">
          <span class="info-label">From:</span>
          <span class="info-value">${escapeHtml(results.senderInfo.from)}</span>
        </div>
        <div class="info-item">
          <span class="info-label">To:</span>
          <span class="info-value">${escapeHtml(results.senderInfo.to)}</span>
        </div>
        <div class="info-item">
          <span class="info-label">Subject:</span>
          <span class="info-value">${escapeHtml(results.senderInfo.subject)}</span>
        </div>
        <div class="info-item">
          <span class="info-label">Date:</span>
          <span class="info-value">${escapeHtml(results.senderInfo.date)}</span>
        </div>
        ${results.senderInfo.replyTo ? `
        <div class="info-item">
          <span class="info-label">Reply-To:</span>
          <span class="info-value">${escapeHtml(results.senderInfo.replyTo)}</span>
        </div>` : ''}
      </div>
    </div>
  `

  // Critical issues
  if (results.issues.length > 0) {
    html += `
      <div class="result-section issues">
        <h3>
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
          </svg>
          Header Issues Found (${results.issues.length})
        </h3>
        <ul>
          ${results.issues.map(issue => `
            <li class="severity-${escapeHtml(issue.severity || 'warning')}">
              <strong>${escapeHtml(issue.check)}</strong>
              <p>${escapeHtml(issue.detail)}</p>
              ${issue.raw ? `<code>${escapeHtml(issue.raw)}</code>` : ''}
            </li>
          `).join('')}
        </ul>
      </div>
    `
  }

  // Warnings
  if (results.warnings.length > 0) {
    html += `
      <div class="result-section warnings">
        <h3>
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
          </svg>
          Warnings (${results.warnings.length})
        </h3>
        <ul>
          ${results.warnings.map(warning => `
            <li>
              <strong>${escapeHtml(warning.check)}</strong>
              <p>${escapeHtml(warning.detail)}</p>
            </li>
          `).join('')}
        </ul>
      </div>
    `
  }

  // Passed checks
  if (results.passed.length > 0) {
    html += `
      <div class="result-section passed">
        <h3>
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          Passed Checks (${results.passed.length})
        </h3>
        <ul>
          ${results.passed.map(pass => `
            <li>
              <strong>${escapeHtml(pass.check)}</strong>
              <p>${escapeHtml(pass.detail)}</p>
            </li>
          `).join('')}
        </ul>
      </div>
    `
  }

  resultsDiv.innerHTML = html
  resultsDiv.classList.remove('hidden')
  resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

function escapeHtml(text) {
  // Security: Handle null, undefined, and non-string inputs
  if (text === null || text === undefined) {
    return ''
  }
  const str = String(text)
  const div = document.createElement('div')
  div.textContent = str
  return div.innerHTML
}

// Button click handler
const checkButton = document.getElementById('check-button')
const textInput = document.getElementById('phishing-input')

checkButton.addEventListener('click', () => {
  const content = textInput.value.trim()

  if (!content) {
    alert('Please enter email headers to check')
    return
  }

  // Security: Limit input size to prevent DoS (500KB max)
  const MAX_INPUT_SIZE = 500 * 1024
  if (content.length > MAX_INPUT_SIZE) {
    alert('Input too large. Please paste only the email headers and body (max 500KB).')
    return
  }

  // Add loading state
  checkButton.classList.add('loading')

  // Analyze headers and body
  setTimeout(() => {
    try {
      const headerAnalyzer = new EmailHeaderAnalyzer(content)
      const headerResults = headerAnalyzer.analyze()

      const bodyAnalyzer = new EmailBodyAnalyzer(content)
      const bodyResults = bodyAnalyzer.analyze()

      renderResults(headerResults, bodyResults)
    } catch (error) {
      console.error('Analysis error:', error)
      // Security: Don't expose internal error details to user
      const safeMessage = error.message
        ? error.message.substring(0, 100).replace(/[<>]/g, '')
        : 'Unknown error'
      alert('Error analyzing email: ' + safeMessage)
    }
    checkButton.classList.remove('loading')
  }, 300)
})

// Allow Ctrl/Cmd + Enter to submit
textInput.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    checkButton.click()
  }
})

// Help modal functionality
const helpButton = document.getElementById('help-button')
const helpModal = document.getElementById('help-modal')
const modalClose = document.getElementById('modal-close')
const modalGotIt = document.getElementById('modal-got-it')
const modalBackdrop = helpModal.querySelector('.modal-backdrop')

function openModal() {
  helpModal.classList.remove('hidden')
  document.body.style.overflow = 'hidden'
}

function closeModal() {
  helpModal.classList.add('hidden')
  document.body.style.overflow = ''
}

helpButton.addEventListener('click', openModal)
modalClose.addEventListener('click', closeModal)
modalGotIt.addEventListener('click', closeModal)
modalBackdrop.addEventListener('click', closeModal)

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !helpModal.classList.contains('hidden')) {
    closeModal()
  }
})
