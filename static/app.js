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

// Menampilkan badge waktu eksekusi (dipakai di semua operasi kriptografi)
function showTiming(elId, ms, label) {
  const el = document.getElementById(elId);
  if (!el) return;
  el.classList.remove("hidden");
  el.innerHTML =
    `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">` +
    `<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg> ` +
    `${label || "Waktu eksekusi"}: ${Number(ms).toFixed(3)} ms`;
}

// Penyimpanan hasil uji terakhir, dipakai oleh tombol "Unduh semua hasil uji"
const testResults = {
  tamper: null,
  avalanche: null,
  entropy: null,
  benchmark: null,
  compare: null,
};

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
  const elapsed = res.headers.get("X-Elapsed-Ms");
  const inputBytes = res.headers.get("X-Input-Bytes");
  document.getElementById("enc-file-result").classList.remove("hidden");
  showTiming("enc-file-timing", elapsed || 0,
    `Waktu enkripsi (${formatBytes(inputBytes)})`);

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
    errBox.textContent = "Gagal: " + err.error;
    errBox.classList.remove("hidden");
    return;
  }
  const elapsed = res.headers.get("X-Elapsed-Ms");
  const outputBytes = res.headers.get("X-Output-Bytes");
  document.getElementById("dec-file-result").classList.remove("hidden");
  showTiming("dec-file-timing", elapsed || 0,
    `Waktu dekripsi (${formatBytes(outputBytes)})`);

  const blob = await res.blob();
  const name = fileInput.files[0].name.endsWith(".brks")
    ? fileInput.files[0].name.slice(0, -5)
    : "dekripsi_" + fileInput.files[0].name;
  downloadBlob(blob, name);
}

function formatBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / 1024 ** 2).toFixed(1)} MB`;
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
  const t0 = performance.now();
  try {
    const data = await postJSON("/api/analysis/tamper-test", { sample_text, password, wrong_password });
    const elapsed = performance.now() - t0;
    document.getElementById("tamper-out").textContent = JSON.stringify(data, null, 2);
    showTiming("tamper-timing", elapsed, "Waktu pengujian (round-trip)");
    testResults.tamper = { input: { sample_text, password, wrong_password }, output: data, elapsed_ms: elapsed };
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
    testResults.avalanche = { input: { algorithm, mode }, output: data, elapsed_ms: elapsed };
    document.getElementById("ava-xlsx-btn").classList.remove("hidden");
  } catch (e) {
    document.getElementById("ava-out").textContent = "Error: " + e.message;
  }
}

let plainHistChart, cipherHistChart;
async function runEntropy() {
  const sample_text = document.getElementById("entropy-text").value;
  const t0 = performance.now();
  try {
    const data = await postJSON("/api/analysis/entropy", { sample_text });
    const elapsed = performance.now() - t0;
    document.getElementById("entropy-summary").textContent =
      `Entropi plainteks: ${data.plaintext_entropy} bit/byte  |  Entropi cipherteks: ${data.ciphertext_entropy} bit/byte (maks. 8.0)`;
    showTiming("entropy-timing", elapsed, "Waktu pengujian");

    const labels = Array.from({ length: 256 }, (_, i) => i);
    if (plainHistChart) plainHistChart.destroy();
    if (cipherHistChart) cipherHistChart.destroy();

    plainHistChart = new Chart(document.getElementById("chart-plain-hist"), {
      type: "bar",
      data: { labels, datasets: [{ label: "Histogram Plainteks", data: data.plaintext_histogram, backgroundColor: "#9C7A3C" }] },
      options: baseChartOptions("Histogram byte — plainteks"),
    });
    cipherHistChart = new Chart(document.getElementById("chart-cipher-hist"), {
      type: "bar",
      data: { labels, datasets: [{ label: "Histogram Cipherteks", data: data.ciphertext_histogram, backgroundColor: "#14171C" }] },
      options: baseChartOptions("Histogram byte — cipherteks (harus rata)"),
    });

    testResults.entropy = { input: { sample_text }, output: data, elapsed_ms: elapsed };
    document.getElementById("entropy-xlsx-btn").classList.remove("hidden");
  } catch (e) {
    alert(e.message);
  }
}

function baseChartOptions(title) {
  return {
    responsive: true,
    plugins: { legend: { display: false }, title: { display: true, text: title, color: "#14171C", font: { family: "IBM Plex Sans" } } },
    scales: {
      x: { display: false },
      y: { ticks: { color: "#5B6270" }, grid: { color: "#DBDFE3" } },
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

    testResults.benchmark = { input: { algorithm, kdf }, output: data, elapsed_ms: elapsed };
    document.getElementById("bench-xlsx-btn").classList.remove("hidden");
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
  const t0 = performance.now();
  try {
    const data = await postJSON("/api/analysis/compare", { size_kb });
    const elapsed = performance.now() - t0;
    const labels = data.comparison.map(c => c.algorithm);
    const encTimes = data.comparison.map(c => c.encrypt_ms);
    const decTimes = data.comparison.map(c => c.decrypt_ms);

    if (compareChart) compareChart.destroy();
    compareChart = new Chart(document.getElementById("chart-compare"), {
      type: "bar",
      data: {
        labels,
        datasets: [
          { label: "Waktu enkripsi (ms)", data: encTimes, backgroundColor: "#9C7A3C" },
          { label: "Waktu dekripsi (ms)", data: decTimes, backgroundColor: "#14171C" },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: { labels: { color: "#14171C", font: { family: "IBM Plex Sans" } } },
          title: { display: true, text: `Perbandingan pada ${size_kb} KB data`, color: "#14171C", font: { family: "IBM Plex Sans" } },
        },
        scales: {
          x: { ticks: { color: "#5B6270" }, grid: { color: "#DBDFE3" } },
          y: { ticks: { color: "#5B6270" }, grid: { color: "#DBDFE3" } },
        },
      },
    });
    showTiming("cmp-timing", elapsed, "Total waktu perbandingan");

    testResults.compare = { input: { size_kb }, output: data, elapsed_ms: elapsed };
    document.getElementById("cmp-xlsx-btn").classList.remove("hidden");
  } catch (e) {
    alert(e.message);
  }
}

// ---------------------------------------------------------------------------
// EKSPOR EXCEL (SheetJS) — memenuhi ketentuan luaran "Data Pengujian .xlsx"
// ---------------------------------------------------------------------------
function downloadWorkbook(wb, filename) {
  XLSX.writeFile(wb, filename);
}

function exportTamperExcel() {
  const r = testResults.tamper;
  if (!r) return;
  const rows = Object.entries(r.output).map(([skenario, hasil]) => ({ Skenario: skenario, Hasil: hasil }));
  const ws = XLSX.utils.json_to_sheet(rows);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, "Uji Ketahanan");
  downloadWorkbook(wb, "brangkass_uji_ketahanan.xlsx");
}

function exportAvalancheExcel() {
  const r = testResults.avalanche;
  if (!r) return;
  const d = r.output;
  const rows = [
    { Bagian: "Gabungan (total)", "Bit Total": d.total_bits, "Bit Berbeda": d.diff_bits, "Persentase (%)": d.percent_changed },
    { Bagian: "Badan cipherteks", "Bit Total": d.body_bits, "Bit Berbeda": d.body_diff_bits, "Persentase (%)": d.body_percent_changed },
    { Bagian: "Authentication tag", "Bit Total": d.tag_bits, "Bit Berbeda": d.tag_diff_bits, "Persentase (%)": d.tag_percent_changed },
  ];
  const ws = XLSX.utils.json_to_sheet(rows);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, "Avalanche Effect");
  downloadWorkbook(wb, "brangkass_avalanche_effect.xlsx");
}

function exportEntropyExcel() {
  const r = testResults.entropy;
  if (!r) return;
  const d = r.output;
  const summary = [
    { Jenis: "Plainteks", "Entropi (bit/byte)": d.plaintext_entropy },
    { Jenis: "Cipherteks", "Entropi (bit/byte)": d.ciphertext_entropy },
  ];
  const histRows = Array.from({ length: 256 }, (_, i) => ({
    "Nilai Byte": i,
    "Frekuensi Plainteks": d.plaintext_histogram[i],
    "Frekuensi Cipherteks": d.ciphertext_histogram[i],
  }));
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(summary), "Ringkasan Entropi");
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(histRows), "Histogram Byte");
  downloadWorkbook(wb, "brangkass_entropi_histogram.xlsx");
}

function exportBenchmarkExcel() {
  const r = testResults.benchmark;
  if (!r) return;
  const rows = r.output.results.map(x => ({
    "Ukuran Data": x.size_label,
    "Waktu Enkripsi (ms)": x.encrypt_ms,
    "Waktu Dekripsi (ms)": x.decrypt_ms,
  }));
  const ws = XLSX.utils.json_to_sheet(rows);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, `Benchmark ${r.output.algorithm}`);
  downloadWorkbook(wb, "brangkass_benchmark_waktu.xlsx");
}

function exportCompareExcel() {
  const r = testResults.compare;
  if (!r) return;
  const rows = r.output.comparison.map(x => ({
    Algoritma: x.algorithm,
    "Ukuran (byte)": x.size_bytes,
    "Waktu Enkripsi (ms)": x.encrypt_ms,
    "Waktu Dekripsi (ms)": x.decrypt_ms,
  }));
  const ws = XLSX.utils.json_to_sheet(rows);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, "Perbandingan Algoritma");
  downloadWorkbook(wb, "brangkass_perbandingan_algoritma.xlsx");
}

function exportAllExcel() {
  const anyResult = Object.values(testResults).some(v => v !== null);
  if (!anyResult) {
    alert("Belum ada hasil uji yang dijalankan. Jalankan minimal satu pengujian di atas terlebih dahulu.");
    return;
  }
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
      "Nilai Byte": i,
      "Frekuensi Plainteks": d.plaintext_histogram[i],
      "Frekuensi Cipherteks": d.ciphertext_histogram[i],
    }));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(histRows), "Histogram Byte");
  }
  if (testResults.benchmark) {
    const rows = testResults.benchmark.output.results.map(x => ({
      "Ukuran Data": x.size_label,
      "Waktu Enkripsi (ms)": x.encrypt_ms,
      "Waktu Dekripsi (ms)": x.decrypt_ms,
    }));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows), "Benchmark Waktu");
  }
  if (testResults.compare) {
    const rows = testResults.compare.output.comparison.map(x => ({
      Algoritma: x.algorithm,
      "Ukuran (byte)": x.size_bytes,
      "Waktu Enkripsi (ms)": x.encrypt_ms,
      "Waktu Dekripsi (ms)": x.decrypt_ms,
    }));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows), "Perbandingan Algoritma");
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
