// ---------------------------------------------------------------------------
// Navigasi sidebar
// ---------------------------------------------------------------------------
document.querySelectorAll(".nav-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(pnl => pnl.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
  });
});

// ---------------------------------------------------------------------------
// Mode terang / gelap
// ---------------------------------------------------------------------------
function applyThemeUI(theme) {
  document.getElementById("theme-icon-sun").classList.toggle("hidden", theme === "dark");
  document.getElementById("theme-icon-moon").classList.toggle("hidden", theme !== "dark");
  document.getElementById("theme-label").textContent = theme === "dark" ? "Mode terang" : "Mode gelap";
}
function toggleTheme() {
  const isDark = document.documentElement.getAttribute("data-theme") === "dark";
  const next = isDark ? "light" : "dark";
  if (next === "dark") {
    document.documentElement.setAttribute("data-theme", "dark");
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
  localStorage.setItem("brangkas-theme", next);
  applyThemeUI(next);
}
applyThemeUI(document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light");

// ---------------------------------------------------------------------------
// Tampilkan / sembunyikan kata sandi
// ---------------------------------------------------------------------------
function togglePassword(inputId, btn) {
  const input = document.getElementById(inputId);
  const isHidden = input.type === "password";
  input.type = isHidden ? "text" : "password";
  btn.innerHTML = isHidden
    ? '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 3l18 18M10.6 10.6a2 2 0 0 0 2.8 2.8M9.4 5.5A10.8 10.8 0 0 1 12 5c7 0 11 7 11 7a13.6 13.6 0 0 1-3.1 3.6M6.3 6.9C3.7 8.6 2 12 2 12s4 7 11 7a10.7 10.7 0 0 0 3.4-.6"/></svg>'
    : '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>';
}

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

function showTiming(elId, ms, label) {
  const el = document.getElementById(elId);
  if (!el) return;
  el.classList.remove("hidden");
  el.innerHTML =
    `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">` +
    `<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg> ` +
    `${label || "Waktu eksekusi"}: ${Number(ms).toFixed(3)} ms`;
}

const testResults = { tamper: null, avalanche: null, entropy: null, benchmark: null };

// ---------------------------------------------------------------------------
// Preview berkas (gambar / generik)
// ---------------------------------------------------------------------------
const IMAGE_EXT = ["jpg", "jpeg", "png", "gif", "webp", "bmp", "svg"];

function fileIconSVG() {
  return '<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.7">' +
    '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>';
}

function renderPreview(container, { name, size, url, isImage }) {
  container.innerHTML = `
    <div class="file-preview">
      ${isImage && url
        ? `<img src="${url}" alt="preview">`
        : `<div class="file-icon">${fileIconSVG()}</div>`}
      <div class="file-meta">
        <div class="file-name">${name}</div>
        <div class="file-size">${formatBytes(size)}</div>
      </div>
    </div>`;
}

function previewFile(inputId, containerId) {
  const input = document.getElementById(inputId);
  const container = document.getElementById(containerId);
  if (!input.files.length) { container.innerHTML = ""; return; }
  const file = input.files[0];
  const ext = file.name.split(".").pop().toLowerCase();
  const isImage = file.type.startsWith("image/") || IMAGE_EXT.includes(ext);

  if (isImage) {
    const reader = new FileReader();
    reader.onload = e => renderPreview(container, { name: file.name, size: file.size, url: e.target.result, isImage: true });
    reader.readAsDataURL(file);
  } else {
    renderPreview(container, { name: file.name, size: file.size, isImage: false });
  }
}

function formatBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / 1024 ** 2).toFixed(1)} MB`;
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
      `Algoritma: ${data.algorithm}  |  KDF: ${data.kdf}  |  Salt: ${data.salt_hex}  |  Nonce: ${data.nonce_hex}`;
    showTiming("enc-timing", data.elapsed_ms, "Waktu enkripsi");
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
    document.getElementById("dec-meta").textContent = `Algoritma: ${data.algorithm}  |  KDF: ${data.kdf}`;
    showTiming("dec-timing", data.elapsed_ms, "Waktu dekripsi");
    resBox.classList.remove("hidden");
  } catch (e) {
    errBox.textContent = "Gagal: " + e.message;
    errBox.classList.remove("hidden");
  }
}

// ---------------------------------------------------------------------------
// BERKAS
// ---------------------------------------------------------------------------
let pendingEncFile = null;  // { blob, filename } menunggu diunduh manual
let pendingDecFile = null;

async function encryptFile() {
  const fileInput = document.getElementById("enc-file-input");
  const password = document.getElementById("enc-file-password").value;
  const algorithm = document.getElementById("enc-file-algo").value;
  const kdf = document.getElementById("enc-file-kdf").value;
  if (!fileInput.files.length || !password) { alert("Pilih berkas dan isi kata sandi."); return; }
  document.getElementById("enc-file-download-btn").classList.add("hidden");

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
  const elapsed = res.headers.get("X-Elapsed-Ms");
  const inputBytes = res.headers.get("X-Input-Bytes");
  document.getElementById("enc-file-result").classList.remove("hidden");
  showTiming("enc-file-timing", elapsed || 0, `Waktu enkripsi (${formatBytes(inputBytes)})`);

  const blob = await res.blob();
  pendingEncFile = { blob, filename: fileInput.files[0].name + ".brks" };
  document.getElementById("enc-file-download-btn").classList.remove("hidden");
}

function downloadEncFile() {
  if (!pendingEncFile) return;
  downloadBlob(pendingEncFile.blob, pendingEncFile.filename);
}

async function decryptFile() {
  const fileInput = document.getElementById("dec-file-input");
  const password = document.getElementById("dec-file-password").value;
  const errBox = document.getElementById("dec-file-error");
  const previewBox = document.getElementById("dec-file-preview");
  errBox.classList.add("hidden");
  previewBox.innerHTML = "";
  document.getElementById("dec-file-download-btn").classList.add("hidden");
  if (!fileInput.files.length || !password) { alert("Pilih berkas .brks dan isi kata sandi."); return; }

  const form = new FormData();
  form.append("file", fileInput.files[0]);
  form.append("password", password);

  const res = await fetch("/api/decrypt-file", { method: "POST", body: form });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Gagal mendekripsi berkas." }));
    errBox.textContent = "Gagal: " + err.error;
    errBox.classList.remove("hidden");
    return;
  }
  const elapsed = res.headers.get("X-Elapsed-Ms");
  const outputBytes = res.headers.get("X-Output-Bytes");
  document.getElementById("dec-file-result").classList.remove("hidden");
  showTiming("dec-file-timing", elapsed || 0, `Waktu dekripsi (${formatBytes(outputBytes)})`);

  const blob = await res.blob();
  const name = fileInput.files[0].name.endsWith(".brks")
    ? fileInput.files[0].name.slice(0, -5)
    : "dekripsi_" + fileInput.files[0].name;

  const ext = name.split(".").pop().toLowerCase();
  const isImage = IMAGE_EXT.includes(ext);
  const objectUrl = URL.createObjectURL(blob);
  renderPreview(previewBox, { name, size: blob.size, url: objectUrl, isImage });
  pendingDecFile = { blob, filename: name };
  document.getElementById("dec-file-download-btn").classList.remove("hidden");
}

function downloadDecFile() {
  if (!pendingDecFile) return;
  downloadBlob(pendingDecFile.blob, pendingDecFile.filename);
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

// ---------------------------------------------------------------------------
// ANALISIS & PENGUJIAN
// ---------------------------------------------------------------------------
async function runTamperTest() {
  const sample_text = document.getElementById("tamper-text").value;
  const password = document.getElementById("tamper-pass").value;
  const wrong_password = document.getElementById("tamper-wrong").value;
  const t0 = performance.now();
  try {
    const data = await postJSON("/api/analysis/tamper-test", { sample_text, password, wrong_password });
    const elapsed = performance.now() - t0;
    document.getElementById("tamper-out").textContent = JSON.stringify(data, null, 2);
    showTiming("tamper-timing", elapsed, "Waktu pengujian (round-trip)");
    testResults.tamper = { output: data };
    document.getElementById("tamper-xlsx-btn").classList.remove("hidden");
  } catch (e) {
    document.getElementById("tamper-out").textContent = "Error: " + e.message;
  }
}

async function runAvalanche() {
  const algorithm = document.getElementById("ava-algo").value;
  const mode = document.getElementById("ava-mode").value;
  const t0 = performance.now();
  try {
    const data = await postJSON("/api/analysis/avalanche", { algorithm, mode });
    const elapsed = performance.now() - t0;
    document.getElementById("ava-out").textContent =
      `Total gabungan: ${data.diff_bits}/${data.total_bits} bit (${data.percent_changed}%)\n` +
      `Badan cipherteks: ${data.body_diff_bits}/${data.body_bits} bit (${data.body_percent_changed}%)\n` +
      `Authentication tag: ${data.tag_diff_bits}/${data.tag_bits} bit (${data.tag_percent_changed}%)\n\n` +
      `Catatan: ${data.note}`;
    showTiming("ava-timing", elapsed, "Waktu pengujian");
    testResults.avalanche = { output: data };
    document.getElementById("ava-xlsx-btn").classList.remove("hidden");
  } catch (e) {
    document.getElementById("ava-out").textContent = "Error: " + e.message;
  }
}

let plainHistChart, cipherHistChart;

// Pustaka Chart.js dimuat dari berkas lokal (static/vendor), bukan CDN, supaya
// tidak gagal ketika jaringan pengguna memblokir domain CDN eksternal. Sebagai
// lapisan pengaman tambahan, bila karena suatu sebab Chart.js tetap gagal
// dimuat, histogram digambar manual langsung ke elemen <canvas> agar diagram
// tetap tampil alih-alih menampilkan error "Chart is not defined".
function isChartJsAvailable() {
  return typeof Chart !== "undefined";
}

function drawHistogramFallback(canvasId, values, color, title) {
  const canvas = document.getElementById(canvasId);
  const ctx = canvas.getContext("2d");
  const cssWidth = canvas.parentElement.clientWidth || 480;
  const cssHeight = canvas.parentElement.clientHeight || 220;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = cssWidth * dpr;
  canvas.height = cssHeight * dpr;
  canvas.style.width = cssWidth + "px";
  canvas.style.height = cssHeight + "px";
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssWidth, cssHeight);

  const padTop = 28, padBottom = 6, padSide = 4;
  const max = Math.max(1, ...values);
  const plotW = cssWidth - padSide * 2;
  const plotH = cssHeight - padTop - padBottom;
  const barW = plotW / values.length;

  ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--ink").trim() || "#171922";
  ctx.font = "600 12px 'IBM Plex Sans', sans-serif";
  ctx.fillText(title, padSide, 16);

  ctx.fillStyle = color;
  values.forEach((v, i) => {
    const h = (v / max) * plotH;
    ctx.fillRect(padSide + i * barW, padTop + (plotH - h), Math.max(1, barW - 0.5), h);
  });
}

async function runEntropy() {
  const sample_text = document.getElementById("entropy-text").value;
  const t0 = performance.now();
  try {
    const data = await postJSON("/api/analysis/entropy", { sample_text });
    const elapsed = performance.now() - t0;
    document.getElementById("entropy-summary").textContent =
      `Entropi plainteks: ${data.plaintext_entropy} bit/byte  |  Entropi cipherteks: ${data.ciphertext_entropy} bit/byte (maks. 8.0)`;
    showTiming("entropy-timing", elapsed, "Waktu pengujian");

    if (isChartJsAvailable()) {
      const labels = Array.from({ length: 256 }, (_, i) => i);
      if (plainHistChart) plainHistChart.destroy();
      if (cipherHistChart) cipherHistChart.destroy();

      const gridColor = getComputedStyle(document.documentElement).getPropertyValue("--border").trim();
      const textColor = getComputedStyle(document.documentElement).getPropertyValue("--ink").trim();

      plainHistChart = new Chart(document.getElementById("chart-plain-hist"), {
        type: "bar",
        data: { labels, datasets: [{ label: "Histogram Plainteks", data: data.plaintext_histogram, backgroundColor: "#4F46E5" }] },
        options: baseChartOptions("Histogram byte — plainteks", textColor, gridColor),
      });
      cipherHistChart = new Chart(document.getElementById("chart-cipher-hist"), {
        type: "bar",
        data: { labels, datasets: [{ label: "Histogram Cipherteks", data: data.ciphertext_histogram, backgroundColor: "#16A34A" }] },
        options: baseChartOptions("Histogram byte — cipherteks (harus rata)", textColor, gridColor),
      });
    } else {
      // Cadangan tanpa Chart.js: gambar histogram manual di canvas
      drawHistogramFallback("chart-plain-hist", data.plaintext_histogram, "#4F46E5", "Histogram byte — plainteks");
      drawHistogramFallback("chart-cipher-hist", data.ciphertext_histogram, "#16A34A", "Histogram byte — cipherteks");
    }

    testResults.entropy = { output: data };
    document.getElementById("entropy-xlsx-btn").classList.remove("hidden");
  } catch (e) {
    alert(e.message);
  }
}

function baseChartOptions(title, textColor, gridColor) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false }, title: { display: true, text: title, color: textColor || "#171922" } },
    scales: {
      x: { display: false },
      y: { ticks: { color: textColor }, grid: { color: gridColor } },
    },
  };
}

async function runBenchmark() {
  const algorithm = document.getElementById("bench-algo").value;
  const kdf = document.getElementById("bench-kdf").value;
  const t0 = performance.now();
  try {
    const data = await postJSON("/api/analysis/benchmark", { algorithm, kdf });
    const elapsed = performance.now() - t0;
    const table = document.getElementById("bench-table");
    const tbody = table.querySelector("tbody");
    tbody.innerHTML = "";
    data.results.forEach(r => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${r.size_label}</td><td>${r.encrypt_ms}</td><td>${r.decrypt_ms}</td>`;
      tbody.appendChild(tr);
    });
    table.classList.remove("hidden");
    showTiming("bench-timing", elapsed, "Total waktu benchmark");

    testResults.benchmark = { output: data };
    document.getElementById("bench-xlsx-btn").classList.remove("hidden");
  } catch (e) {
    alert(e.message);
  }
}

// ---------------------------------------------------------------------------
// EKSPOR EXCEL (SheetJS)
// ---------------------------------------------------------------------------
function isXlsxAvailable() {
  return typeof XLSX !== "undefined";
}
function downloadWorkbook(wb, filename) {
  if (!isXlsxAvailable()) {
    alert("Pustaka Excel (SheetJS) gagal dimuat. Muat ulang halaman (Ctrl/Cmd+Shift+R) dan coba lagi.");
    return;
  }
  XLSX.writeFile(wb, filename);
}

function exportTamperExcel() {
  if (!isXlsxAvailable()) { alert("Pustaka Excel (SheetJS) gagal dimuat. Muat ulang halaman (Ctrl/Cmd+Shift+R) dan coba lagi."); return; }
  const r = testResults.tamper;
  if (!r) return;
  const rows = Object.entries(r.output).map(([skenario, hasil]) => ({ Skenario: skenario, Hasil: hasil }));
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows), "Uji Ketahanan");
  downloadWorkbook(wb, "brangkass_uji_ketahanan.xlsx");
}

function exportAvalancheExcel() {
  if (!isXlsxAvailable()) { alert("Pustaka Excel (SheetJS) gagal dimuat. Muat ulang halaman (Ctrl/Cmd+Shift+R) dan coba lagi."); return; }
  const d = testResults.avalanche?.output;
  if (!d) return;
  const rows = [
    { Bagian: "Gabungan (total)", "Bit Total": d.total_bits, "Bit Berbeda": d.diff_bits, "Persentase (%)": d.percent_changed },
    { Bagian: "Badan cipherteks", "Bit Total": d.body_bits, "Bit Berbeda": d.body_diff_bits, "Persentase (%)": d.body_percent_changed },
    { Bagian: "Authentication tag", "Bit Total": d.tag_bits, "Bit Berbeda": d.tag_diff_bits, "Persentase (%)": d.tag_percent_changed },
  ];
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows), "Avalanche Effect");
  downloadWorkbook(wb, "brangkass_avalanche_effect.xlsx");
}

function exportEntropyExcel() {
  if (!isXlsxAvailable()) { alert("Pustaka Excel (SheetJS) gagal dimuat. Muat ulang halaman (Ctrl/Cmd+Shift+R) dan coba lagi."); return; }
  const d = testResults.entropy?.output;
  if (!d) return;
  const summary = [
    { Jenis: "Plainteks", "Entropi (bit/byte)": d.plaintext_entropy },
    { Jenis: "Cipherteks", "Entropi (bit/byte)": d.ciphertext_entropy },
  ];
  const histRows = Array.from({ length: 256 }, (_, i) => ({
    "Nilai Byte": i, "Frekuensi Plainteks": d.plaintext_histogram[i], "Frekuensi Cipherteks": d.ciphertext_histogram[i],
  }));
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(summary), "Ringkasan Entropi");
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(histRows), "Histogram Byte");
  downloadWorkbook(wb, "brangkass_entropi_histogram.xlsx");
}

function exportBenchmarkExcel() {
  if (!isXlsxAvailable()) { alert("Pustaka Excel (SheetJS) gagal dimuat. Muat ulang halaman (Ctrl/Cmd+Shift+R) dan coba lagi."); return; }
  const r = testResults.benchmark;
  if (!r) return;
  const rows = r.output.results.map(x => ({ "Ukuran Data": x.size_label, "Waktu Enkripsi (ms)": x.encrypt_ms, "Waktu Dekripsi (ms)": x.decrypt_ms }));
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows), `Benchmark ${r.output.algorithm}`);
  downloadWorkbook(wb, "brangkass_benchmark_waktu.xlsx");
}

function exportAllExcel() {
  if (!isXlsxAvailable()) { alert("Pustaka Excel (SheetJS) gagal dimuat. Muat ulang halaman (Ctrl/Cmd+Shift+R) dan coba lagi."); return; }
  const anyResult = Object.values(testResults).some(v => v !== null);
  if (!anyResult) { alert("Belum ada hasil uji yang dijalankan. Jalankan minimal satu pengujian di atas terlebih dahulu."); return; }
  const wb = XLSX.utils.book_new();

  if (testResults.tamper) {
    const rows = Object.entries(testResults.tamper.output).map(([skenario, hasil]) => ({ Skenario: skenario, Hasil: hasil }));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows), "Uji Ketahanan");
  }
  if (testResults.avalanche) {
    const d = testResults.avalanche.output;
    const rows = [
      { Bagian: "Gabungan (total)", "Bit Total": d.total_bits, "Bit Berbeda": d.diff_bits, "Persentase (%)": d.percent_changed },
      { Bagian: "Badan cipherteks", "Bit Total": d.body_bits, "Bit Berbeda": d.body_diff_bits, "Persentase (%)": d.body_percent_changed },
      { Bagian: "Authentication tag", "Bit Total": d.tag_bits, "Bit Berbeda": d.tag_diff_bits, "Persentase (%)": d.tag_percent_changed },
    ];
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows), "Avalanche Effect");
  }
  if (testResults.entropy) {
    const d = testResults.entropy.output;
    const summary = [
      { Jenis: "Plainteks", "Entropi (bit/byte)": d.plaintext_entropy },
      { Jenis: "Cipherteks", "Entropi (bit/byte)": d.ciphertext_entropy },
    ];
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(summary), "Ringkasan Entropi");
    const histRows = Array.from({ length: 256 }, (_, i) => ({
      "Nilai Byte": i, "Frekuensi Plainteks": d.plaintext_histogram[i], "Frekuensi Cipherteks": d.ciphertext_histogram[i],
    }));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(histRows), "Histogram Byte");
  }
  if (testResults.benchmark) {
    const rows = testResults.benchmark.output.results.map(x => ({ "Ukuran Data": x.size_label, "Waktu Enkripsi (ms)": x.encrypt_ms, "Waktu Dekripsi (ms)": x.decrypt_ms }));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows), "Benchmark Waktu");
  }
  downloadWorkbook(wb, "brangkass_data_pengujian.xlsx");
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
