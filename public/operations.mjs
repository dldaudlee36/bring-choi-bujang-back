const panel = document.querySelector('#operations');
const status = document.querySelector('#ops-status');
const summary = document.querySelector('#ops-summary');
const table = document.querySelector('#ops-rows');
const refresh = document.querySelector('#ops-refresh');
const download = document.querySelector('#ops-download');
let currentReport = null;
const label = { matched: '기대와 일치', mismatch: '기대와 다름', not_run: '미실행' };

function element(tag, text) {
  const node = document.createElement(tag);
  node.textContent = text;
  return node;
}

async function loadReport() {
  refresh.disabled = true;
  download.disabled = true;
  currentReport = null;
  summary.replaceChildren();
  table.replaceChildren();
  status.textContent = '서버에서 실제 점검을 실행하고 기록을 읽는 중입니다.';
  try {
    const response = await fetch('/api/checks', { cache: 'no-store', headers: { Accept: 'application/json' } });
    const report = await response.json();
    if (!response.ok || report.schema !== 'aleph.operations.v1' || !Array.isArray(report.cases)) throw new Error();
    currentReport = report;
    status.textContent = `커밋 ${report.commit?.slice(0, 12) ?? '확인 불가'} · 확인 ${report.checkedAt} · 기록 ID ${report.reportId}`;
    for (const [name, value] of [
      ['자기 점검', `${report.summary.total}개 · 일치 ${report.summary.matched} · 불일치 ${report.summary.mismatch} · 미실행 ${report.summary.notRun}`],
      ['실제 HTTP / 가상 규칙', `${report.summary.liveExecuted} / ${report.summary.syntheticExecuted}개`],
      ['판정기 규칙', report.policy.rules.join(', ')],
      ['탐지 사건', `고정 가상 사건 ${report.detection.events}개 → ${report.detection.action}`],
      ['실제 권한 회수', label[report.revocation.status]],
      ['복구 기준 정책', `${report.recovery.policyVersion.slice(0, 12)} · 운영 복구 ${label[report.recovery.status]}`],
      ['공식 41종 총공세', `이 기록에서 실행 ${report.assault.executed} · 방어 확인 ${report.assault.blocked} · 미실행 ${report.assault.notRun}`],
    ]) {
      summary.append(element('dt', name), element('dd', value));
    }
    for (const row of report.cases) {
      const tr = document.createElement('tr');
      for (const text of [
        row.stage,
        row.id,
        row.type === 'normal' ? '정상' : '금지/추가 확인',
        row.source === 'live_api' ? '실제 API' : '가상 규칙 API',
        row.expected,
        row.observed,
        label[row.result],
        row.requestId ?? '—',
        row.checkedAt ?? '—',
      ]) {
        tr.append(element('td', text));
      }
      table.append(tr);
    }
    download.disabled = false;
  } catch {
    status.textContent = '서버 기록을 읽지 못했습니다. 수치와 결과를 표시하지 않습니다.';
  } finally {
    refresh.disabled = false;
  }
}

refresh.addEventListener('click', () => void loadReport());
download.addEventListener('click', () => {
  if (!currentReport) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(currentReport, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = `operations-${currentReport.commit?.slice(0, 12) ?? 'unknown'}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

if (panel) void loadReport();
