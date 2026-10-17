/**
 * Valide et décompose une chaîne d'URL.
 */
function parseUrl(urlString) {
  try {
    const parsed = new URL(urlString);
    
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return {
        valid: false,
        error: `Protocole non supporté ("${parsed.protocol}"). Seuls http: et https: sont autorisés.`
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
      error: 'Format d\'URL invalide. N\'oubliez pas d\'inclure "http://" ou "https://".'
    };
  }
}

/**
 * Moteur de détection heuristique.
 * @param {object} parsedUrl 
 * @param {string} rawUrl
 * @returns {object} Analyse complète avec findings et niveau de risque
 */
function analyzeUrl(parsedUrl, rawUrl) {
  const findings = [];
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const isIpAddress = ipv4Regex.test(parsedUrl.hostname);

  // Règle 1 : Utilisation directe d'une adresse IP
  if (isIpAddress) {
    findings.push({
      severity: 'SUSPECT',
      weight: 3,
      message: 'L\'URL utilise une adresse IP directe au lieu d\'un nom de domaine.'
    });
  }

  // Règle 2 : Présence du symbole '@'
  if (rawUrl.includes('@')) {
    findings.push({
      severity: 'ÉLEVÉ',
      weight: 4,
      message: 'L\'URL contient le symbole "@", souvent utilisé pour masquer la destination réelle.'
    });
  }

  // Règle 3 : Nombre excessif de sous-domaines (ignoré si c'est une adresse IP)
  if (!isIpAddress) {
    const dotCount = (parsedUrl.hostname.match(/\./g) || []).length;
    if (dotCount >= 3) {
      findings.push({
        severity: 'SUSPECT',
        weight: 2,
        message: `Nom d'hôte avec une structure complexe de sous-domaines (${dotCount} points détectés).`
      });
    }
  }

  // Règle 4 : Utilisation du protocole HTTP non chiffré
  if (parsedUrl.protocol === 'http:') {
    findings.push({
      severity: 'FAIBLE',
      weight: 1,
      message: 'L\'URL utilise le protocole HTTP non chiffré (absence de HTTPS).'
    });
  }

  // Règle 5 : Présence de mots-clés sensibles dans l'URL
  const sensitiveKeywords = ['login', 'verify', 'update', 'account', 'banking', 'secure', 'signin'];
  const lowerUrl = rawUrl.toLowerCase();
  const foundKeywords = sensitiveKeywords.filter(keyword => lowerUrl.includes(keyword));
  
  if (foundKeywords.length > 0) {
    findings.push({
      severity: 'INFORMACIONAL',
      weight: 1,
      message: `Contient des mots-clés sensibles récurrents dans les cibles de phishing : ${foundKeywords.join(', ')}.`
    });
  }

  // Calcul du score global de risque
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