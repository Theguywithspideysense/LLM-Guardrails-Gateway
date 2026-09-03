// Behavior checks run the real dashboard script against a minimal DOM substitute.
// These cover decisions and safe text rendering, not browser layout or accessibility.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');

class Element {
  constructor(tag = 'div', text = '') {
    this.tagName = tag; this.children = []; this.className = ''; this.dataset = {};
    this.attributes = {}; this.listeners = {}; this.value = ''; this.hidden = false;
    this.disabled = false; this.textContent = text;
    this.classList = {
      toggle: (name, enabled) => {
        const names = new Set(this.className.split(/\s+/).filter(Boolean));
        if (enabled) names.add(name); else names.delete(name);
        this.className = [...names].join(' ');
      }
    };
  }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  focus() {}
  reportValidity() { return Boolean(this.value.trim()); }
}

async function fixture() {
  const html = fs.readFileSync(path.join(root, 'dashboard/index.html'), 'utf8');
  const ids = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(match => [match[1], new Element()]));
  const risks = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(risk => {
    const el = new Element(); el.dataset.risk = risk; return el;
  });
  const tabs = ['console', 'history', 'policies'].map(tab => {
    const el = new Element('button'); el.dataset.tab = tab; return el;
  });
  const exampleButtons = ['safe', 'pii', 'injection'].map(example => {
    const el = new Element('button'); el.dataset.example = example; return el;
  });
  ids.get('historyFilter').value = 'all';
  let nextResponse = {status: 200, body: decision()};
  let history = [];
  let rejectChat = false;
  const fetchCalls = [];
  const context = vm.createContext({
    console, AbortController, Date, Map, Set, String, Number, JSON,
    location: {port: '8000'},
    navigator: {clipboard: {writeText: async () => {}}},
    setTimeout, clearTimeout, setInterval: () => {},
    document: {
      hidden: false,
      getElementById: id => { assert.ok(ids.has(id), `Missing HTML element: ${id}`); return ids.get(id); },
      createElement: tag => new Element(tag),
      addEventListener: () => {},
      querySelectorAll: selector => ({'.risk-card': risks, '.tab': tabs, '[data-example]': exampleButtons}[selector] || [])
    },
    fetch: async (url, options = {}) => {
      fetchCalls.push({url, options});
      if (url === '/chat' && rejectChat) throw new TypeError('Synthetic network failure');
      const body = url === '/chat' ? nextResponse.body : {
        '/health': {status: 'healthy', model: 'qwen2.5-coder:7b', ollama: 'available', model_available: true, semantic_enabled: true},
        '/stats': {total_requests: 0, blocked_requests: 0, failed_requests: 0, latency_ms: 0, risk_score: 0, risk_level: 'LOW'},
        '/history': {history}, '/risk-config': {max_input_length: 8000},
        '/policies': {policies: {}, allowed_actions: {}}
      }[url];
      const status = url === '/chat' ? nextResponse.status : 200;
      return {ok: status < 400, status, json: async () => body, headers: {get: () => '60'}};
    }
  });
  vm.runInContext(fs.readFileSync(path.join(root, 'dashboard/assets/app.js'), 'utf8'), context);
  await new Promise(resolve => setImmediate(resolve));
  return {ids, risks, tabs, context, fetchCalls,
    respond(body, status = 200) { nextResponse = {body, status}; },
    setHistory(value) { history = value; },
    failNetwork() { rejectChat = true; },
    async send() {
      ids.get('promptInput').value = 'Explain decorators';
      await ids.get('promptForm').listeners.submit({preventDefault() {}});
    }
  };
}

function decision(overrides = {}) {
  return {success: true, blocked: false, action: 'allow', stage: 'complete', reason: 'CHECKS_PASSED',
    risk: {level: 'LOW', score: 0}, violations: [], checks: [], warnings: [],
    response: 'Safe model answer', latency_ms: 150, ...overrides};
}

test('an allowed answer is visible and prompt is sent in the expected API shape', async () => {
  const f = await fixture(); await f.send();
  assert.equal(f.ids.get('requestStatus').textContent, 'Request allowed');
  assert.equal(f.ids.get('answerSection').hidden, false);
  assert.equal(f.ids.get('modelAnswer').textContent, 'Safe model answer');
  assert.equal(JSON.parse(f.fetchCalls.find(call => call.url === '/chat').options.body).message, 'Explain decorators');
});

test('HTTP 503 classifier failure never appears as allowed', async () => {
  const f = await fixture();
  f.respond(decision({success: false, action: 'error', stage: 'semantic', reason: 'SEMANTIC_CHECK_FAILED', response: null}), 503);
  await f.send();
  assert.equal(f.ids.get('resultBadge').textContent, 'FAILED');
  assert.equal(f.ids.get('answerSection').hidden, true);
  assert.match(f.ids.get('resultMessage').textContent, /No answer was generated/);
});

test('output blocks say the model answered but output was withheld', async () => {
  const f = await fixture();
  f.respond(decision({success: false, blocked: true, action: 'block', stage: 'output', response: null,
    violations: [{guardrail: 'output_secrets'}], checks: [{guardrail: 'output_secrets', status: 'triggered'}]}));
  await f.send();
  assert.match(f.ids.get('resultMessage').textContent, /output was withheld/);
  assert.equal(f.ids.get('answerSection').hidden, true);
  const guard = f.ids.get('guardGrid').children.find(el => el.dataset.guardrail === 'output_secrets');
  assert.match(guard.className, /triggered/);
  const skipped = f.ids.get('guardGrid').children.find(el => el.dataset.guardrail === 'pii');
  assert.match(skipped.textContent, /WAITING/);
});

test('redaction keeps a visible answer and a distinct decision badge', async () => {
  const f = await fixture(); f.respond(decision({action: 'redact', redacted: true, response: '[EMAIL_REDACTED]'}));
  await f.send();
  assert.equal(f.ids.get('resultBadge').textContent, 'REDACTED');
  assert.equal(f.ids.get('answerSection').hidden, false);
});

test('rate-limit errors show retry guidance and release the submit button', async () => {
  const f = await fixture(); f.respond({error: 'Rate limit exceeded'}, 429); await f.send();
  assert.equal(f.ids.get('resultBadge').textContent, 'FAILED');
  assert.match(f.ids.get('resultMessage').textContent, /60 seconds/);
  assert.equal(f.ids.get('sendButton').disabled, false);
});

test('network failures hide any previously visible model answer', async () => {
  const f = await fixture(); await f.send(); f.failNetwork(); await f.send();
  assert.equal(f.ids.get('resultBadge').textContent, 'FAILED');
  assert.equal(f.ids.get('answerSection').hidden, true);
  assert.equal(f.ids.get('modelAnswer').textContent, '');
});

test('history uses text nodes for untrusted preview text and honors filters', async () => {
  const f = await fixture();
  const preview = '<img src=x onerror=alert(1)>';
  f.setHistory([{timestamp: '2026-01-01T12:00:00+00:00', prompt_preview: preview, action: 'block',
    risk: {level: 'HIGH'}, violations: [{guardrail: 'prompt_injection'}]}]);
  await vm.runInContext('refreshHistory()', f.context);
  const row = f.ids.get('historyList').children[0];
  const prompt = row.children.find(el => el.className === 'log-prompt');
  assert.equal(prompt.textContent, 'Prompt: ' + preview);
  assert.equal(prompt.children.length, 0);
  f.ids.get('historyFilter').value = 'allow'; f.ids.get('historyFilter').listeners.change();
  assert.match(f.ids.get('historyList').textContent, /No requests match/);
});
