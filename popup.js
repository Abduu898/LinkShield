document.getElementById('scanBtn').addEventListener('click', function () {
  const inputUrl = document.getElementById('urlInput').value.trim();
  const resultDiv = document.getElementById('result');

  if (!inputUrl) {
    resultDiv.innerHTML = '<strong>Erreur :</strong> Veuillez entrer une URL.';
    return;
  }

  const parsedResult = parseUrl(inputUrl);

  if (!parsedResult.valid) {
    resultDiv.innerHTML = `<strong>URL Invalide :</strong> ${parsedResult.error}`;
    return;
  }

  // Lancement de l'analyse heuristique avec les deux arguments
  const findings = analyzeUrl(parsedResult, inputUrl);

  // Formatage de l'affichage des résultats
  let findingsHtml = '';
  if (findings.length === 0) {
    findingsHtml = '<li>Aucun indicateur suspect détecté pour le moment.</li>';
  } else {
    findings.forEach(finding => {
      findingsHtml += `<li style="color: #c0392b;"><strong>[${finding.severity}]</strong> ${finding.message}</li>`;
    });
  }

  resultDiv.innerHTML = `
    <strong>Résultat du scan pour :</strong> <code>${parsedResult.hostname}</code>
    <ul style="padding-left: 20px; margin-top: 10px;">
      ${findingsHtml}
    </ul>
  `;
});

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
 * Moteur de détection heuristique simple.
 * @param {object} parsedUrl 
 * @param {string} rawUrl
 * @returns {Array} Liste des anomalies détectées
 */
function analyzeUrl(parsedUrl, rawUrl) {
  const findings = [];

  // Règle 1 : Utilisation directe d'une adresse IP
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(parsedUrl.hostname)) {
    findings.push({
      severity: 'SUSPECT',
      message: 'L\'URL utilise une adresse IP directe au lieu d\'un nom de domaine.'
    });
  }

  // Règle 2 : Présence du symbole '@'
  if (rawUrl.includes('@')) {
    findings.push({
      severity: 'ÉLEVÉ',
      message: 'L\'URL contient le symbole "@", souvent utilisé pour masquer la destination réelle.'
    });
  }

  // Règle 3 : Nombre excessif de sous-domaines
  const dotCount = (parsedUrl.hostname.match(/\./g) || []).length;
  if (dotCount >= 3) {
    findings.push({
      severity: 'SUSPECT',
      message: `Nom d'hôte avec une structure complexe de sous-domaines (${dotCount} points détectés).`
    });
  }

  return findings;
}