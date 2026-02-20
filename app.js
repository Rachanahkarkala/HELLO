const csvInput = document.getElementById('csvInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const downloadJsonBtn = document.getElementById('downloadJsonBtn');
const statusEl = document.getElementById('status');
const fileBadge = document.getElementById('fileBadge');
const tableBody = document.querySelector('#ringTable tbody');
const suspiciousList = document.getElementById('suspiciousList');

const totalAccountsEl = document.getElementById('totalAccounts');
const suspiciousCountEl = document.getElementById('suspiciousCount');
const ringCountEl = document.getElementById('ringCount');
const processingTimeEl = document.getElementById('processingTime');

let parsedTransactions = [];
let lastResult = null;

csvInput.addEventListener('change', () => {
  const hasFile = csvInput.files.length > 0;
  analyzeBtn.disabled = !hasFile;
  downloadJsonBtn.disabled = true;
  fileBadge.textContent = hasFile ? csvInput.files[0].name : 'No file selected';
  statusEl.textContent = hasFile ? 'Dataset loaded. Click analyze to run all detection passes.' : 'Awaiting dataset upload.';
});

analyzeBtn.addEventListener('click', () => {
  if (!csvInput.files.length) return;

  statusEl.style.color = '#93c5fd';
  statusEl.textContent = 'Analyzing graph patterns...';
  analyzeBtn.disabled = true;

  const file = csvInput.files[0];
  Papa.parse(file, {
    header: true,
    skipEmptyLines: true,
    complete: ({ data, errors }) => {
      if (errors.length) {
        statusEl.style.color = '#fca5a5';
        statusEl.textContent = `CSV parsing error: ${errors[0].message}`;
        analyzeBtn.disabled = false;
        return;
      }

      try {
        const start = performance.now();
        parsedTransactions = normalizeTransactions(data);
        const result = detectPatterns(parsedTransactions, start);
        lastResult = result;

        drawGraph(parsedTransactions, result);
        renderRings(result.fraud_rings);
        renderSuspicious(result.suspicious_accounts);
        renderSummary(result.summary);

        downloadJsonBtn.disabled = false;
        statusEl.style.color = '#86efac';
        statusEl.textContent = `Analysis complete. ${result.summary.suspicious_accounts_flagged} suspicious accounts flagged across ${result.summary.fraud_rings_detected} rings.`;
      } catch (error) {
        statusEl.style.color = '#fca5a5';
        statusEl.textContent = `Analysis failed: ${error.message}`;
      }
      analyzeBtn.disabled = false;
    }
  });
});

downloadJsonBtn.addEventListener('click', () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'mulesight_detection_output.json';
  link.click();
  URL.revokeObjectURL(url);
});

function renderSummary(summary) {
  totalAccountsEl.textContent = summary.total_accounts_analyzed;
  suspiciousCountEl.textContent = summary.suspicious_accounts_flagged;
  ringCountEl.textContent = summary.fraud_rings_detected;
  processingTimeEl.textContent = `${summary.processing_time_seconds.toFixed(3)}s`;
}

function normalizeTransactions(rows) {
  const required = ['transaction_id', 'sender_id', 'receiver_id', 'amount', 'timestamp'];
  if (!rows.length) throw new Error('No rows found.');

  required.forEach((field) => {
    if (!(field in rows[0])) throw new Error(`Missing required column: ${field}`);
  });

  return rows.map((row, idx) => {
    const amount = Number(row.amount);
    const timestamp = new Date(row.timestamp.replace(' ', 'T') + 'Z');
    if (!row.sender_id || !row.receiver_id || Number.isNaN(amount) || Number.isNaN(timestamp.getTime())) {
      throw new Error(`Invalid row at line ${idx + 2}`);
    }
    return {
      transaction_id: row.transaction_id,
      sender_id: row.sender_id.trim(),
      receiver_id: row.receiver_id.trim(),
      amount,
      timestamp,
      raw_timestamp: row.timestamp
    };
  });
}

function detectPatterns(transactions, start) {
  const accountStats = new Map();
  const graph = new Map();

  transactions.forEach((tx) => {
    addSetMap(graph, tx.sender_id, tx.receiver_id);

    if (!accountStats.has(tx.sender_id)) accountStats.set(tx.sender_id, { in: 0, out: 0, txCount: 0, totalIn: 0, totalOut: 0 });
    if (!accountStats.has(tx.receiver_id)) accountStats.set(tx.receiver_id, { in: 0, out: 0, txCount: 0, totalIn: 0, totalOut: 0 });

    accountStats.get(tx.sender_id).out += 1;
    accountStats.get(tx.sender_id).txCount += 1;
    accountStats.get(tx.sender_id).totalOut += tx.amount;
    accountStats.get(tx.receiver_id).in += 1;
    accountStats.get(tx.receiver_id).txCount += 1;
    accountStats.get(tx.receiver_id).totalIn += tx.amount;
  });

  const rings = [];
  const accountPatterns = new Map();

  detectCycles(graph).forEach((ring) => {
    const ringId = ringIdentifier(rings.length + 1);
    rings.push({ ring_id: ringId, member_accounts: [...ring], pattern_type: 'cycle', risk_score: scoreRing('cycle', ring.length, 1) });
    ring.forEach((account) => addPattern(accountPatterns, account, `cycle_length_${ring.length}`, ringId));
  });

  detectSmurfing(transactions).forEach((ring) => {
    const ringId = ringIdentifier(rings.length + 1);
    rings.push({ ...ring, ring_id: ringId });
    ring.member_accounts.forEach((account) => addPattern(accountPatterns, account, ring.pattern_type, ringId));
  });

  detectShellChains(transactions, accountStats).forEach((ring) => {
    const ringId = ringIdentifier(rings.length + 1);
    rings.push({ ...ring, ring_id: ringId });
    ring.member_accounts.forEach((account) => addPattern(accountPatterns, account, 'layered_shell', ringId));
  });

  const suspiciousAccounts = Array.from(accountPatterns.entries()).map(([account, entry]) => {
    const stats = accountStats.get(account) || { in: 0, out: 0, totalIn: 0, totalOut: 0 };
    const base = entry.patterns.length * 22;
    const velocity = Math.min(20, (stats.in + stats.out) * 1.2);
    const flowSkew = Math.min(18, (Math.abs(stats.totalIn - stats.totalOut) / Math.max(1, stats.totalIn + stats.totalOut)) * 40);

    return {
      account_id: account,
      suspicion_score: Number(Math.min(100, base + velocity + flowSkew).toFixed(1)),
      detected_patterns: [...new Set(entry.patterns)],
      ring_id: entry.ring_id
    };
  }).sort((a, b) => b.suspicion_score - a.suspicion_score);

  const end = performance.now();
  return {
    suspicious_accounts: suspiciousAccounts,
    fraud_rings: rings,
    summary: {
      total_accounts_analyzed: accountStats.size,
      suspicious_accounts_flagged: suspiciousAccounts.length,
      fraud_rings_detected: rings.length,
      processing_time_seconds: Number(((end - start) / 1000).toFixed(3))
    }
  };
}

function detectCycles(graph) {
  const cycles = new Set();
  const nodes = [...graph.keys()];

  const dfs = (start, current, path, visited) => {
    if (path.length > 5) return;
    for (const next of graph.get(current) || []) {
      if (next === start && path.length >= 3 && path.length <= 5) {
        cycles.add(normalizeCycle(path).join('>'));
      } else if (!visited.has(next) && path.length < 5) {
        visited.add(next);
        path.push(next);
        dfs(start, next, path, visited);
        path.pop();
        visited.delete(next);
      }
    }
  };

  nodes.forEach((node) => dfs(node, node, [node], new Set([node])));
  return [...cycles].map((cycle) => cycle.split('>'));
}

function detectSmurfing(transactions) {
  const rings = [];
  const byReceiver = new Map();
  const bySender = new Map();

  transactions.forEach((tx) => {
    pushMap(byReceiver, tx.receiver_id, tx);
    pushMap(bySender, tx.sender_id, tx);
  });

  byReceiver.forEach((incoming, receiver) => {
    const uniqueSenders = new Set(incoming.map((tx) => tx.sender_id));
    if (uniqueSenders.size >= 10 && withinWindow(incoming, 72)) {
      rings.push({ member_accounts: [...uniqueSenders, receiver], pattern_type: 'fan_in', risk_score: scoreRing('fan_in', uniqueSenders.size + 1, 1) });
    }
  });

  bySender.forEach((outgoing, sender) => {
    const uniqueReceivers = new Set(outgoing.map((tx) => tx.receiver_id));
    if (uniqueReceivers.size >= 10 && withinWindow(outgoing, 72)) {
      rings.push({ member_accounts: [sender, ...uniqueReceivers], pattern_type: 'fan_out', risk_score: scoreRing('fan_out', uniqueReceivers.size + 1, 1) });
    }
  });

  return rings;
}

function detectShellChains(transactions, stats) {
  const outgoing = new Map();
  transactions.forEach((tx) => pushMap(outgoing, tx.sender_id, tx));

  const rings = [];
  for (const tx of transactions) {
    for (const tx2 of outgoing.get(tx.receiver_id) || []) {
      for (const tx3 of outgoing.get(tx2.receiver_id) || []) {
        const chain = [tx.sender_id, tx.receiver_id, tx2.receiver_id, tx3.receiver_id];
        const intermediates = [tx.receiver_id, tx2.receiver_id];
        const isShellLike = intermediates.every((account) => {
          const txCount = stats.get(account)?.txCount || 0;
          return txCount >= 2 && txCount <= 3;
        });
        if (isShellLike) rings.push({ member_accounts: chain, pattern_type: 'shell_chain', risk_score: scoreRing('shell_chain', chain.length, 1) });
      }
    }
  }
  return uniqueRings(rings);
}

function renderRings(rings) {
  tableBody.innerHTML = '';
  rings.forEach((ring) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${ring.ring_id}</td>
      <td>${ring.pattern_type}</td>
      <td>${ring.member_accounts.length}</td>
      <td>${ring.risk_score}</td>
      <td>${ring.member_accounts.join(', ')}</td>
    `;
    tableBody.appendChild(row);
  });
}

function renderSuspicious(accounts) {
  suspiciousList.innerHTML = '';
  accounts.slice(0, 30).forEach((acc, idx) => {
    const li = document.createElement('li');
    li.style.animationDelay = `${idx * 0.015}s`;
    li.textContent = `${acc.account_id} — score ${acc.suspicion_score} (${acc.detected_patterns.join(', ')})`;
    suspiciousList.appendChild(li);
  });
}

function drawGraph(transactions, result) {
  const container = document.getElementById('graph');
  const suspiciousSet = new Set(result.suspicious_accounts.map((a) => a.account_id));
  const ringColor = ['#f43f5e', '#f97316', '#eab308', '#22c55e', '#14b8a6', '#3b82f6', '#8b5cf6'];
  const accountRing = new Map();

  result.fraud_rings.forEach((ring, idx) => {
    ring.member_accounts.forEach((account) => {
      if (!accountRing.has(account)) accountRing.set(account, ringColor[idx % ringColor.length]);
    });
  });

  const nodeSet = new Set();
  transactions.forEach((tx) => {
    nodeSet.add(tx.sender_id);
    nodeSet.add(tx.receiver_id);
  });

  const nodes = [...nodeSet].map((id) => ({
    id,
    label: id,
    shape: 'dot',
    size: suspiciousSet.has(id) ? 24 : 14,
    borderWidth: suspiciousSet.has(id) ? 3 : 1,
    color: {
      background: accountRing.get(id) || (suspiciousSet.has(id) ? '#f59e0b' : '#60a5fa'),
      border: suspiciousSet.has(id) ? '#ef4444' : '#1e293b'
    },
    font: { color: '#e2e8f0', strokeWidth: 0 },
    title: `<b>${id}</b><br/>Suspicious: ${suspiciousSet.has(id) ? 'Yes' : 'No'}`
  }));

  const edges = transactions.map((tx) => ({
    from: tx.sender_id,
    to: tx.receiver_id,
    arrows: 'to',
    label: `${tx.amount}`,
    font: { size: 9, color: '#cbd5e1' },
    color: { color: '#64748b', opacity: 0.7 }
  }));

  new vis.Network(container, { nodes, edges }, {
    physics: { stabilization: false, barnesHut: { springLength: 130, avoidOverlap: 0.7 } },
    interaction: { hover: true, zoomView: true, dragView: true },
    edges: { smooth: { type: 'dynamic' } }
  });
}

function ringIdentifier(n) {
  return `RING_${String(n).padStart(3, '0')}`;
}

function addSetMap(map, key, value) {
  if (!map.has(key)) map.set(key, new Set());
  map.get(key).add(value);
}

function pushMap(map, key, value) {
  if (!map.has(key)) map.set(key, []);
  map.get(key).push(value);
}

function addPattern(map, account, pattern, ringId) {
  if (!map.has(account)) map.set(account, { patterns: [], ring_id: ringId });
  const entry = map.get(account);
  entry.patterns.push(pattern);
  if (!entry.ring_id) entry.ring_id = ringId;
}

function withinWindow(txs, hours) {
  const sorted = [...txs].sort((a, b) => a.timestamp - b.timestamp);
  const start = sorted[0]?.timestamp?.getTime();
  const end = sorted[sorted.length - 1]?.timestamp?.getTime();
  if (!start || !end) return false;
  return (end - start) / (1000 * 60 * 60) <= hours;
}

function scoreRing(type, size, density) {
  const base = { cycle: 80, fan_in: 72, fan_out: 72, shell_chain: 76 }[type] || 65;
  return Number(Math.min(99.9, base + size * 1.8 + density * 2).toFixed(1));
}

function normalizeCycle(path) {
  const variants = [];
  for (let i = 0; i < path.length; i += 1) variants.push([...path.slice(i), ...path.slice(0, i)]);
  return variants.sort((a, b) => a.join('>').localeCompare(b.join('>')))[0];
}

function uniqueRings(rings) {
  const seen = new Set();
  return rings.filter((ring) => {
    const key = [...ring.member_accounts].sort().join('|') + ring.pattern_type;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
