document.addEventListener('DOMContentLoaded', loadHistory);

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

  // Analyse
  const analysis = analyzeUrl(parsedResult, inputUrl);

  // Couleurs
  let riskColor = '#27ae60';
  if (analysis.riskLevel === 'MODÉRÉ') riskColor = '#f39c12';
  if (analysis.riskLevel === 'ÉLEVÉ') riskColor = '#c0392b';

  // Formatage des anomalies
  let findingsHtml = '';
  if (analysis.findings.length === 0) {
    findingsHtml = '<li>Aucun indicateur suspect détecté par les règles heuristiques.</li>';
  } else {
    analysis.findings.forEach(item => {
      findingsHtml += `<li><strong>[${item.severity}]</strong> ${item.message}</li>`;
    });
  }

  resultDiv.innerHTML = `
    <div style="margin-bottom: 10px;">
      <strong>Niveau de risque estimé :</strong> 
      <span style="color: ${riskColor}; font-weight: bold;">${analysis.riskLevel}</span>
    </div>
    <strong>Analyse de :</strong> <code>${parsedResult.hostname}</code>
    <ul style="padding-left: 20px; margin-top: 8px;">
      ${findingsHtml}
    </ul>
    <p style="font-size: 11px; color: #666; margin-top: 12px; border-top: 1px solid #eee; padding-top: 6px;">
      <em>Note : L'absence d'alerte ne garantit pas qu'un lien soit totalement sans danger.</em>
    </p>
  `;

  // Enregistrement dans l'historique
  saveToHistory(parsedResult.hostname, analysis.riskLevel);
});

// Vider l'historique
document.getElementById('clearHistoryBtn').addEventListener('click', function () {
  chrome.storage.local.set({ scanHistory: [] }, function () {
    renderHistory([]);
  });
});

/**
 * Sauvegarde un scan dans chrome.storage.local (max 5 entrées).
 */
function saveToHistory(hostname, riskLevel) {
  chrome.storage.local.get(['scanHistory'], function (data) {
    let history = data.scanHistory || [];
    
    // Ajout du scan au début
    history.unshift({ hostname, riskLevel, timestamp: new Date().toLocaleTimeString() });

    // Conservation des 5 derniers éléments uniquement
    if (history.length > 5) {
      history = history.slice(0, 5);
    }

    chrome.storage.local.set({ scanHistory: history }, function () {
      renderHistory(history);
    });
  });
}

/**
 * Charge l'historique au démarrage de la popup.
 */
function loadHistory() {
  chrome.storage.local.get(['scanHistory'], function (data) {
    renderHistory(data.scanHistory || []);
  });
}

/**
 * Affiche la liste de l'historique dans le DOM.
 */
function renderHistory(history) {
  const historyList = document.getElementById('historyList');
  
  if (history.length === 0) {
    historyList.innerHTML = '<li>Aucun scan enregistré.</li>';
    return;
  }

  let html = '';
  history.forEach(item => {
    html += `<li><code>${item.hostname}</code> — <strong>${item.riskLevel}</strong> (${item.timestamp})</li>`;
  });
  
  historyList.innerHTML = html;
}