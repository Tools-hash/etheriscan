// Utility function untuk mendapatkan elemen DOM dari id
const getElement = id => document.getElementById(id);

// Updates hasil display dengan konten
const updateResult = (content, display = true) =>  {
    const result = getElement('result');
    result.style.display = display ? 'block' : 'none';
    result.innerHTML = content;
}

// Spinner loading
const showLoading = message => updateResult(`
    <div class="loading">
        <p>${message}</p>
        <div class="spinner"></div>
    </div>    
`);

// Displays pesan err
const showError = message => updateResult(`
    <p class="error">${message}</p>
`);

// Function untuk membuat autentikasi API req ke VirusTotal
async function makeRequest(url, options={}) {
    const response = await fetch(url, {
        ...options,
        headers: {
            "x-apikey": API_KEY,
            ...options.headers
        }
    });

    // Handle req yang gagal
    if (!response.ok) {
        const error = await response.json().catch(() => 
                    ({ error:  { message: response.statusText } }));
        throw new Error(error.error?.message || 'Permintaan Gagal!');
    }

    return response.json(); // Parsing req JSON
}

// Handles proses dari scanning URL menggunakan VirusTotal
async function scanURL() {
    const url = getElement('urlInput').value.trim();

    if (!url) return showError('Masukan URL!');

    try {
        new URL(url);
    } catch {
        return showError('Masukkan URL valid! (e.g., https://example.com)');
    }

    try {
        showLoading('Scanning URL, Mohon Menunggu..');

        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ type: "url", url })
        });

        if (!response.ok) throw new Error("Request gagal");

        const submitResult = await response.json();

        if (!submitResult.data?.id) {
            throw new Error('Gagal mendapatkan analisis ID');
        }

        await new Promise(resolve => setTimeout(resolve, 3000));
        showLoading('Mendapatkan hasil scan..');
        await pollAnalysisResults(submitResult.data.id);

    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

// Handles proses dari scanning file menggunakan VirusTotal
async function scanFile() {
    const file = getElement('fileInput').files[0];
    if (!file) return showError('Masukan File!');
    if (file.size > 32 * 1024 * 1024) return showError('Ukuran file melebihi batas 32MB!');

    try {
        showLoading('Mengupload file..');

        const formData = new FormData();
        formData.append('file', file);

        // kirim ke backend (api/scan.js)
        const response = await fetch("/api/scan", {
            method: "POST",
            body: formData
        });

        if (!response.ok) throw new Error("Upload gagal!");

        const uploadResult = await response.json();

        if (!uploadResult.data?.id) {
            throw new Error('Gagal mendapatkan file ID!');
        }

        await new Promise(resolve => setTimeout(resolve, 3000));
        showLoading('Mendapatkan hasil scan..');

        // lanjut polling hasilnya (masih bisa ke backend juga biar aman)
        const analysisResult = await fetch(`/api/scan?id=${uploadResult.data.id}`);
        const resultJson = await analysisResult.json();

        if (!resultJson.data?.id) {
            throw new Error('Gagal mendapatkan hasil analisis!');
        }

        await pollAnalysisResults(resultJson.data.id, file.name);

    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

// Polls VirusTotal untuk hasil analisis, coba lagi sampai selesai atau batas waktu habis
async function pollAnalysisResults(analysisId, fileName = '') {
    const maxAttempts = 20;
    let attempts = 0;
    let interval = 2000;

    while (attempts < maxAttempts) {
        try {
            showLoading(`Menganalisis: ${fileName ? ` ${fileName}` :  ''}... (${((maxAttempts - attempts) * interval /  1000).toFixed(0)}s)`);

            const report = await makeRequest(`https://www.virustotal.com/api/v3/analyses/${analysisId}`);
            const status = report.data?.attributes?.status;

            if (!status) throw new Error('Respon analisis invalid!');

            if (status === 'completed') {
                showFormattedResult(report);
                break;
            }

            if (status === 'failed') {
                throw new Error('Analisis gagal!');
            }

            if (++attempts >= maxAttempts) {
                throw new Error('Analisis timeout - coba lagi..');
            }

            // Menambahkkan interval diantara percobaan ulang
            interval = Math.min(interval * 1.5, 8000);
            await new Promise(resolve => setTimeout(resolve, interval));
        } catch (error) {
            showError(`Error: ${error.message}`);
            break;
        }
    }
}

// Formats dan displays hasil analisis di UI
function showFormattedResult(data) {
    if (!data?.data?.attributes?.stats) return showError('Respon format invalid!');

    const stats = data.data.attributes.stats;
    const total = Object.values(stats).reduce((sum, val) => sum + val, 0);

    if (!total) return showError('Tidak ada hasil analisis yang tersedia');

    const getPercent = val => ((val / total) * 100).toFixed(1);

    const categories = {
        malicious: { color: 'malicious', label: 'File Jahat' },
        suspicious: { color: 'suspicious', label: 'File Mencurigakan' },
        harmless: { color: 'safe', label: 'File Bersih'},
        undetected: { color: 'undetected', label: 'Tidak Terdeteksi'}
    }

    const percents = Object.keys(categories).reduce((acc, key) => {
        acc[key] = getPercent(stats[key]);
        return acc;
    }, {});

    // Menentukan keputusan
    const verdict = stats.malicious > 0 ? 'Malicious' :
                    stats.suspicious > 0 ? 'Suspicious' : 'Safe';
    const verdictClass = stats.malicious > 0 ? 'malicious' :
                         stats.suspicious > 0 ? 'suspicious' : 'safe';

    // Render hasil ke UI
    updateResult(`
        <h3>Hasil Scan</h3>
        <div class="scan-stats">
            <p><strong>Verdict: </strong> <span class="${verdictClass}">${verdict}</span></p>
            <div class="progress-section">
                <div class="progress-label">
                    <span>Hasil Deteksi</span>
                    <span class="progress-percent">${percents.malicious}% Tingkat Deteksi</span>
                </div>
                <div class="progress-stacked">
                    ${Object.entries(categories).map(([key, { color }]) => `
                        <div class="progress-bar ${color}" style="width: ${percents[key]}%" 
                             title="${categories[key].label}: ${stats[key]} (${percents[key]}%)">
                                <span class="progress-label-overlay">${stats[key]}</span>
                             </div>
                    `).join('')}
                </div>
                <div class="progress-legend">
                    ${Object.entries(categories).map(([key, { color, label }]) => `
                        <div class="legend-item">
                            <span class="legend-color ${color}"></span>
                            <span>${label} (${percents[key]}%)</span>

                        </div>
                    `).join('')}
                </div>
            </div>
            <div class="detection-details">
                ${Object.entries(categories).map(([key, { color, label }]) => `
                    <div class="detail-item ${color}">
                        <span class="detail-label">${label}</span>
                        <span class="detail-value">${stats[key]}</span>
                        <span class="detail-percent">${percents[key]}%</span>
                    </div>
                `).join('')}
            </div>
        </div>
        <button onclick="showFullReport(this.getAttribute('data-report'))"
                data-report='${JSON.stringify(data)}'>Lihat Hasil Lengkap</button>
    `);

    // Trigger animasi
    setTimeout(() => getElement('result').querySelector('.progress-stacked').classList.add('animate'), 1000);
}

// menampilkan laporan terperinci, dengan hasil deteksi engine-by-engine
function showFullReport(reportData) {
    const data = typeof reportData === 'string' ? JSON.parse(reportData) : reportData;
    const modal = getElement('fullReportModal');
    const results = data.data?.attributes?.results;

    getElement('fullReportContent').innerHTML = `
    <h3>Rincian Hasil Lengkap</h3>
    ${results ? `
        <table>
            <tr><th>Hasil</th><th>Mesin</th></tr>
            ${Object.entries(results).map(([engine, { category }]) => `
                <tr>
                    <td>${engine}</td>
                    <td class="${category === 'malicious' ? 'malicious' : category === 'suspicious' ? 'suspicious' : 'safe'}">
                        ${category}
                    </td>
                </tr>
            `).join('')}
        </table>    
    ` : '<p>Tidak ada hasil yang tersedia!</p>'}
    `;

    modal.style.display = 'block';
    modal.offsetHeight;
    modal.classList.add('show');
}

// Tutup hasil total
const closeModal = () => {
    const modal = getElement('fullReportModal');
    modal.classList.remove('show');
    setTimeout(() => modal.style.display =  'none', 300);
}

// Tutup hasil menggunakan offside click
window.addEventListener('load', () => {
    const modal = getElement('fullReportModal');
    window.addEventListener('click', e => e.target === modal && closeModal());
});