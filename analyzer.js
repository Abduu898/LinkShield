/**
 * Validates and parses an input URL string.
 * @param {string} urlString 
 * @returns {object} Parsed URL properties or validation error message
 */
function parseUrl(urlString) {
  try {
    const parsed = new URL(urlString);
    
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return {
        valid: false,
        error: `Unsupported protocol ("${parsed.protocol}"). Only http: and https: are supported.`
      };
    }

    return {
      valid: true,
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      pathname: parsed.pathname
    };
  } catch (err) {
    return {
      valid: false,
      error: 'Invalid URL format. Make sure to include "http://" or "https://".'
    };
  }
}

/**
 * Core heuristic analysis engine.
 * @param {object} parsedUrl - Output object from parseUrl
 * @param {string} rawUrl - Full unparsed input URL string
 * @returns {object} Complete analysis including findings, risk level, and total weight score
 */
function analyzeUrl(parsedUrl, rawUrl) {
  const findings = [];
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const isIpAddress = ipv4Regex.test(parsedUrl.hostname);

  // Rule 1: Direct IPv4 Address
  if (isIpAddress) {
    findings.push({
      severity: 'SUSPECT',
      weight: 3,
      message: 'The URL uses a direct IP address instead of a domain name.'
    });
  }

  // Rule 2: '@' Masking Symbol
  if (rawUrl.includes('@')) {
    findings.push({
      severity: 'ÉLEVÉ',
      weight: 4,
      message: 'The URL contains an "@" symbol, often used to obscure the true destination host.'
    });
  }

  // Rule 3: Complex Subdomain Structure (Skipped for IP addresses)
  if (!isIpAddress) {
    const lowerHost = parsedUrl.hostname.toLowerCase();
    const commonTwoLevelTlds = ['.co.uk', '.com.fr', '.gouv.fr', '.org.uk', '.co.jp', '.com.au'];
    
    let dotCount = (lowerHost.match(/\./g) || []).length;
    
    // Adjust dot count for multi-part TLD suffixes
    if (commonTwoLevelTlds.some(tld => lowerHost.endsWith(tld))) {
      dotCount -= 1;
    }

    if (dotCount >= 3) {
      findings.push({
        severity: 'SUSPECT',
        weight: 2,
        message: `Complex subdomain structure detected (${dotCount} dots in hostname).`
      });
    }
  }

  // Rule 4: Unencrypted Protocol (HTTP)
  if (parsedUrl.protocol === 'http:') {
    findings.push({
      severity: 'FAIBLE',
      weight: 1,
      message: 'The URL uses unencrypted HTTP protocol (absence of HTTPS).'
    });
  }

  // Rule 5: Target Keywords in Hostname
  const sensitiveKeywords = ['login', 'verify', 'update', 'account', 'banking', 'secure', 'signin'];
  const lowerHostname = parsedUrl.hostname.toLowerCase();
  const foundKeywords = sensitiveKeywords.filter(keyword => lowerHostname.includes(keyword));
  
  if (foundKeywords.length > 0) {
    findings.push({
      severity: 'INFORMACIONAL',
      weight: 1,
      message: `The hostname contains sensitive keywords: ${foundKeywords.join(', ')}.`
    });
  }

  // Calculate cumulative risk score
  const totalWeight = findings.reduce((sum, item) => sum + item.weight, 0);
  let riskLevel = 'FAIBLE';
  
  if (totalWeight >= 4) {
    riskLevel = 'ÉLEVÉ';
  } else if (totalWeight >= 2) {
    riskLevel = 'MODÉRÉ';
  }

  return {
    findings: findings,
    riskLevel: riskLevel,
    score: totalWeight
  };
}