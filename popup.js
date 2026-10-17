document.getElementById('scanBtn').addEventListener('click', function () {
  const url = document.getElementById('urlInput').value.trim();
  const resultDiv = document.getElementById('result');

  if (!url) {
    resultDiv.innerHTML = '<strong>Error:</strong> Please enter a URL first.';
    return;
  }

  // Demonstration output — real analysis will be added in Phase 2
  resultDiv.innerHTML = `<strong>Demonstration Mode:</strong> Received input: <code>${url}</code>`;
});