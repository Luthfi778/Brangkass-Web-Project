// ---------------------------------------------------------------------------
// Navigasi tab
// ---------------------------------------------------------------------------
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
  });
});

function copyText(id) {
  const el = document.getElementById(id);
  el.select();
  document.execCommand("copy");
}

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Terjadi kesalahan.");
  return data;
}

// ---------------------------------------------------------------------------
// TEKS
// ---------------------------------------------------------------------------
async function encryptText() {
  const plaintext = document.getElementById("enc-plaintext").value;
  const password = document.getElementById("enc-password").value;
  const algorithm = document.getElementById("enc-algo").value;
  const kdf = document.getElementById("enc-kdf").value;
  try {
    const data = await postJSON("/api/encrypt-text", { plaintext, password, algorithm, kdf });
    document.getElementById("enc-out-b64").value = data.ciphertext_base64;
    document.getElementById("enc-out-hex").value = data.ciphertext_hex;
    document.getElementById("enc-meta").textContent =
      `Algoritma: ${data.algorithm} | KDF: ${data.kdf} | Salt: ${data.salt_hex} | Nonce: ${data.nonce_hex} | Waktu: ${data.elapsed_ms} ms`;
    document.getElementById("enc-result").classList.remove("hidden");
  } catch (e) {
    alert(e.message);
  }
}

async function decryptText() {
  const ciphertext = document.getElementById("dec-ciphertext").value;
  const encoding = document.getElementById("dec-encoding").value;
  const password = document.getElementById("dec-password").value;
  const errBox = document.getElementById("dec-error");
  const resBox = document.getElementById("dec-result");
  errBox.classList.add("hidden");
  resBox.classList.add("hidden");
  try {
    const data = await postJSON("/api/decrypt-text", { ciphertext, encoding, password });
    document.getElementById("dec-out").value = data.plaintext;
    document.getElementById("dec-meta").textContent =
      `Algoritma: ${data.algorithm} | KDF: ${data.kdf} | Waktu: ${data.elapsed_ms} ms`;
    resBox.classList.remove("hidden");
  } catch (e) {
    errBox.textContent = "❌ " + e.message;
    errBox.classList.remove("hidden");
  }
}

// ---------------------------------------------------------------------------
// BERKAS
// ---------------------------------------------------------------------------
async function encryptFile() {
  const fileInput = document.getElementById("enc-file-input");
  const password = document.getElementById("enc-file-password").value;
  const algorithm = document.getElementById("enc-file-algo").value;
  const kdf = document.getElementById("enc-file-kdf").value;
  if (!fileInput.files.length || !password) { alert("Pilih berkas dan isi kata sandi."); return; }

  const form = new FormData();
  form.append("file", fileInput.files[0]);
  form.append("password", password);
  form.append("algorithm", algorithm);
  form.append("kdf", kdf);

  const res = await fetch("/api/encrypt-file", { method: "POST", body: form });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Gagal mengenkripsi berkas." }));
    alert(err.error);
    return;
  }
  const blob = await res.blob();
  downloadBlob(blob, fileInput.files[0].name + ".brks");
}

async function decryptFile() {
  const fileInput = document.getElementById("dec-file-input");
  const password = document.getElementById("dec-file-password").value;
  const errBox = document.getElementById("dec-file-error");
  errBox.classList.add("hidden");
  if (!fileInput.files.length || !password) { alert("Pilih berkas .brks dan isi kata sandi."); return; }

  const form = new FormData();
  form.append("file", fileInput.files[0]);
  form.append("password", password);

  const res = await fetch("/api/decrypt-file", { method: "POST", body: form });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Gagal mendekripsi berkas." }));
    errBox.textContent = "❌ " + err.error;
    errBox.classList.remove("hidden");
    return;
  }
  const blob = await res.blob();
  const name = fileInput.files[0].name.endsWith(".brks")
    ? fileInput.files[0].name.slice(0, -5)
    : "dekripsi_" + fileInput.files[0].name;
  downloadBlob(blob, name);
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// ANALISIS & PENGUJIAN
// ---------------------------------------------------------------------------
async function runTamperTest() {
  const sample_text = document.getElementById("tamper-text").value;
  const password = document.getElementById("tamper-pass").value;
  const wrong_password = document.getElementById("tamper-wrong").value;
  try {
    const data = await postJSON("/api/analysis/tamper-test", { sample_text, password, wrong_password });
    document.getElementById("tamper-out").textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    document.getElementById("tamper-out").textContent = "Error: " + e.message;
  }
}

async function runAvalanche() {
  const algorithm = document.getElementById("ava-algo").value;
  const mode = document.getElementById("ava-mode").value;
  try {
    const data = await postJSON("/api/analysis/avalanche", { algorithm, mode });
    document.getElementById("ava-out").textContent =
      `Total gabungan: ${data.diff_bits}/${data.total_bits} bit (${data.percent_changed}%)\n` +
      `Badan cipherteks: ${data.body_diff_bits}/${data.body_bits} bit (${data.body_percent_changed}%)\n` +
      `Authentication tag: ${data.tag_diff_bits}/${data.tag_bits} bit (${data.tag_percent_changed}%)\n\n` +
      `Catatan: ${data.note}`;
  } catch (e) {
    document.getElementById("ava-out").textContent = "Error: " + e.message;
  }
}

let plainHistChart, cipherHistChart;
async function runEntropy() {
  const sample_text = document.getElementById("entropy-text").value;
  try {
    const data = await postJSON("/api/analysis/entropy", { sample_text });
    document.getElementById("entropy-summary").textContent =
      `Entropi plainteks: ${data.plaintext_entropy} bit/byte  |  Entropi cipherteks: ${data.ciphertext_entropy} bit/byte (maks. 8.0)`;

    const labels = Array.from({ length: 256 }, (_, i) => i);
    if (plainHistChart) plainHistChart.destroy();
    if (cipherHistChart) cipherHistChart.destroy();

    plainHistChart = new Chart(document.getElementById("chart-plain-hist"), {
      type: "bar",
      data: { labels, datasets: [{ label: "Histogram Plainteks", data: data.plaintext_histogram, backgroundColor: "#5b8cff" }] },
      options: baseChartOptions("Histogram Byte — Plainteks"),
    });
    cipherHistChart = new Chart(document.getElementById("chart-cipher-hist"), {
      type: "bar",
      data: { labels, datasets: [{ label: "Histogram Cipherteks", data: data.ciphertext_histogram, backgroundColor: "#33d69f" }] },
      options: baseChartOptions("Histogram Byte — Cipherteks (harus rata)"),
    });
  } catch (e) {
    alert(e.message);
  }
}

function baseChartOptions(title) {
  return {
    responsive: true,
    plugins: { legend: { display: false }, title: { display: true, text: title, color: "#e7ecf7" } },
    scales: {
      x: { display: false },
      y: { ticks: { color: "#9aa7c2" }, grid: { color: "#2a3450" } },
    },
  };
}

async function runBenchmark() {
  const algorithm = document.getElementById("bench-algo").value;
  const kdf = document.getElementById("bench-kdf").value;
  try {
    const data = await postJSON("/api/analysis/benchmark", { algorithm, kdf });
    const table = document.getElementById("bench-table");
    const tbody = table.querySelector("tbody");
    tbody.innerHTML = "";
    data.results.forEach(r => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${r.size_label}</td><td>${r.encrypt_ms}</td><td>${r.decrypt_ms}</td>`;
      tbody.appendChild(tr);
    });
    table.classList.remove("hidden");
  } catch (e) {
    alert(e.message);
  }
}

// ---------------------------------------------------------------------------
// PERBANDINGAN ALGORITMA
// ---------------------------------------------------------------------------
let compareChart;
async function runCompare() {
  const size_kb = document.getElementById("cmp-size").value;
  try {
    const data = await postJSON("/api/analysis/compare", { size_kb });
    const labels = data.comparison.map(c => c.algorithm);
    const encTimes = data.comparison.map(c => c.encrypt_ms);
    const decTimes = data.comparison.map(c => c.decrypt_ms);

    if (compareChart) compareChart.destroy();
    compareChart = new Chart(document.getElementById("chart-compare"), {
      type: "bar",
      data: {
        labels,
        datasets: [
          { label: "Waktu Enkripsi (ms)", data: encTimes, backgroundColor: "#5b8cff" },
          { label: "Waktu Dekripsi (ms)", data: decTimes, backgroundColor: "#33d69f" },
        ],
      },
      options: {
        responsive: true,
        plugins: { legend: { labels: { color: "#e7ecf7" } }, title: { display: true, text: `Perbandingan pada ${size_kb} KB data`, color: "#e7ecf7" } },
        scales: {
          x: { ticks: { color: "#9aa7c2" }, grid: { color: "#2a3450" } },
          y: { ticks: { color: "#9aa7c2" }, grid: { color: "#2a3450" } },
        },
      },
    });
  } catch (e) {
    alert(e.message);
  }
}

// ---------------------------------------------------------------------------
// API JWT
// ---------------------------------------------------------------------------
let currentToken = null;
async function getToken() {
  try {
    const data = await postJSON("/api/v1/token", { api_key: "demo-client", api_secret: "demo-secret-ubah-ini" });
    currentToken = data.access_token;
    document.getElementById("api-token-out").textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    document.getElementById("api-token-out").textContent = "Error: " + e.message;
  }
}

let lastApiCiphertext = null;
async function apiEncrypt() {
  if (!currentToken) { alert("Ambil token JWT terlebih dahulu."); return; }
  const plaintext = document.getElementById("api-plaintext").value;
  const password = document.getElementById("api-password").value;
  try {
    const res = await fetch("/api/v1/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + currentToken },
      body: JSON.stringify({ plaintext, password, algorithm: "aes-gcm" }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    lastApiCiphertext = data.ciphertext_base64;
    document.getElementById("api-encrypt-out").textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    document.getElementById("api-encrypt-out").textContent = "Error: " + e.message;
  }
}

async function apiDecrypt() {
  if (!currentToken) { alert("Ambil token JWT terlebih dahulu."); return; }
  if (!lastApiCiphertext) { alert("Enkripsi teks via API terlebih dahulu."); return; }
  const password = document.getElementById("api-password").value;
  try {
    const res = await fetch("/api/v1/decrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + currentToken },
      body: JSON.stringify({ ciphertext_base64: lastApiCiphertext, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    document.getElementById("api-decrypt-out").textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    document.getElementById("api-decrypt-out").textContent = "Error: " + e.message;
  }
}
