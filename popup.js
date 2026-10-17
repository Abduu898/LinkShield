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

  // Appel du moteur d'analyse
  const analysis = analyzeUrl(parsedResult, inputUrl);

  // Détermination de la couleur selon le risque
  let riskColor = '#27ae60'; // Vert (Faible)
  if (analysis.riskLevel === 'MODÉRÉ') riskColor = '#f39c12'; // Orange
  if (analysis.riskLevel === 'ÉLEVÉ') riskColor = '#c0392b'; // Rouge

  // Génération de la liste des anomalies
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
});