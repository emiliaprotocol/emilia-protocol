#!/usr/bin/env node
/**
 * EP Invariant Coverage Gate
 *
 * Checks that every critical protocol invariant has coverage across all
 * four layers: code guard, test, formal model, and documentation.
 *
 * Exits with code 1 if any critical invariant is missing ANY coverage layer.
 *
 * Usage: node scripts/check-invariant-coverage.js
 *
 * @license Apache-2.0
 */

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Configuration — all paths are hardcoded literals from project root
// ---------------------------------------------------------------------------

const ROOT = path.resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// File collection — uses only hardcoded paths, no dynamic path construction
// ---------------------------------------------------------------------------

/**
 * Recursively collect file paths under a hardcoded directory.
 * Only called with string literals; never with user input.
 */
function collectFilesFromAbsolute(absoluteDir) {
  const results = [];
  if (!fs.existsSync(absoluteDir)) return results;
  const stack = [absoluteDir];
  while (stack.length > 0) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const ent of entries) {
      if (ent.name.startsWith('.') || ent.name === 'node_modules') continue;
      // Build child path safely: ent.name from readdirSync is OS-provided,
      // and we verify it contains no traversal components.
      if (ent.name.includes('..') || ent.name.includes('/')) continue;
      const child = dir + path.sep + ent.name;
      if (ent.isDirectory()) {
        stack.push(child);
      } else if (ent.isFile()) {
        results.push(child);
      }
    }
  }
  return results;
}

/**
 * Check whether any file in fileList contains the literal string `term`.
 * Uses String.prototype.includes (no RegExp, no dynamic patterns).
 * Returns { found, file } where file is relative to ROOT.
 */
function anyFileContains(fileList, term) {
  const lowerTerm = term.toLowerCase();
  for (const filePath of fileList) {
    let content;
    try { content = fs.readFileSync(filePath, 'utf-8'); } catch (_) { continue; }
    if (content.toLowerCase().includes(lowerTerm)) {
      return { found: true, file: path.relative(ROOT, filePath) };
    }
  }
  return { found: false, file: null };
}

/**
 * Check whether any term in the list is found in any file in fileList.
 * Returns { found, file, term }.
 */
function searchFiles(fileList, terms) {
  for (const term of terms) {
    const result = anyFileContains(fileList, term);
    if (result.found) {
      return { found: true, file: result.file, term };
    }
  }
  return { found: false, file: null, term: null };
}

// ---------------------------------------------------------------------------
// Pre-collect all files from hardcoded directories (once, at startup)
// ---------------------------------------------------------------------------

// These paths are string-literal concatenations, not dynamic user input.
const libFiles = collectFilesFromAbsolute(ROOT + path.sep + 'lib');
const testFiles = collectFilesFromAbsolute(ROOT + path.sep + 'tests');
const formalFiles = collectFilesFromAbsolute(ROOT + path.sep + 'formal');
const docFiles = collectFilesFromAbsolute(ROOT + path.sep + 'docs');

// ---------------------------------------------------------------------------
// Critical invariants — each must have all four coverage layers
// ---------------------------------------------------------------------------

const CRITICAL_INVARIANTS = [
  {
    id: 'S1',
    name: 'Consume-once safety',
    codeTerms: ['23505', 'ALREADY_CONSUMED', 'consumed_at'],
    testTerms: ['consume', 'ALREADY_CONSUMED'],
    formalTerms: ['ConsumeOnceSafety', 'NoDoubleConsumption', 'UniqueConsumption'],
    docTerms: ['Consume-once', 'exactly once'],
  },
  {
    id: 'S2',
    name: 'Consume requires verified',
    codeTerms: ['ConsumeRequiresVerified', 'status', 'verified'],
    testTerms: ['consume', 'verified'],
    formalTerms: ['ConsumeRequiresVerified', 'ConsumedHasConsumption'],
    docTerms: ['Consume requires', 'verified'],
  },
  {
    id: 'S3',
    name: 'Revoked is terminal',
    codeTerms: ['revoked', 'REVOKED'],
    testTerms: ['revok', 'REVOKED'],
    formalTerms: ['RevokedIsTerminal', 'RevokedTerminal', 'RevokedNeverConsumed'],
    docTerms: ['Revoked is terminal'],
  },
  {
    id: 'S4',
    name: 'Event coverage',
    codeTerms: ['requireHandshakeEvent', 'appendProtocolEvent', 'EVENT_WRITE_REQUIRED'],
    testTerms: ['event', 'requireHandshakeEvent'],
    formalTerms: ['EventCoverage', 'EventTypeConsistency', 'EventCompleteness', 'EventStateCorrespondence'],
    docTerms: ['Event coverage', 'durable event'],
  },
  {
    id: 'S5',
    name: 'Policy required for verification',
    codeTerms: ['resolvePolicy', 'policy_hash_mismatch', 'policyHash'],
    testTerms: ['policy', 'policyHash'],
    formalTerms: ['PolicyRequired', 'PolicyHashMismatchDetection', 'PolicyVersionConsistency', 'PolicyHashConsistency'],
    docTerms: ['Policy required', 'policy'],
  },
  {
    id: 'S6',
    name: 'Expired is terminal',
    codeTerms: ['expired', 'checkNotExpired'],
    testTerms: ['expire', 'checkNotExpired'],
    formalTerms: ['ExpiredIsTerminal', 'ExpiredTerminal'],
    docTerms: ['Expired is terminal'],
  },
  {
    id: 'S7',
    name: 'Rejected is terminal',
    codeTerms: ['rejected', 'REJECTED'],
    testTerms: ['reject'],
    formalTerms: ['RejectedIsTerminal', 'RejectedTerminal'],
    docTerms: ['Rejected is terminal'],
  },
  {
    id: 'S8',
    name: 'Write-bypass safety',
    codeTerms: ['WRITE_DISCIPLINE_VIOLATION', 'getGuardedClient', 'protocolWrite'],
    testTerms: ['write', 'WRITE_DISCIPLINE', 'protocolWrite'],
    formalTerms: ['WriteBypassSafety', 'WritePathExclusivity', 'WritePathExclusive', 'NoDirectWriteMutations'],
    docTerms: ['protocolWrite', 'write'],
  },
  {
    id: 'S9',
    name: 'Terminal state irreversibility',
    codeTerms: ['terminal', 'consumed', 'revoked', 'expired', 'rejected'],
    testTerms: ['terminal'],
    formalTerms: ['TerminalStateIrreversibility', 'TerminalStateIntegrity', 'TerminalEscapeAttempt'],
    docTerms: ['terminal'],
  },
  {
    id: 'S10',
    name: 'Delegate cannot exceed principal',
    codeTerms: ['delegat', 'scope', 'principal'],
    testTerms: ['delegat'],
    formalTerms: ['DelegateCannotExceedPrincipal', 'DelegationScopeBounded', 'DelegationScopeRespected'],
    docTerms: ['delegat'],
  },
  {
    id: 'S11',
    name: 'Delegation acyclicity',
    codeTerms: ['delegat', 'chain'],
    testTerms: ['delegat'],
    formalTerms: ['DelegationAcyclicity', 'DelegationAcyclic', 'NoDelegationCycles', 'NoSelfDelegation'],
    docTerms: ['delegat'],
  },
  {
    id: 'S12',
    name: 'Policy-hash mismatch detection',
    codeTerms: ['policy_hash_mismatch', 'computePolicyHash', 'policyHash'],
    testTerms: ['policy_hash', 'mismatch'],
    formalTerms: ['PolicyHashMismatchDetection', 'PolicyVersionConsistency', 'PolicyHashConsistency', 'PolicyChange'],
    docTerms: ['policy_hash_mismatch', 'hash'],
  },
  {
    id: 'S13',
    name: 'Event completeness',
    codeTerms: ['requireHandshakeEvent', 'appendProtocolEvent'],
    testTerms: ['event'],
    formalTerms: ['EventCompleteness', 'EventStateCorrespondence', 'EventStateExactCorrespondence'],
    docTerms: ['event'],
  },
];

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  console.log('='.repeat(78));
  console.log('EP Invariant Coverage Gate');
  console.log('='.repeat(78));
  console.log('');

  const results = [];
  let failures = 0;

  for (const inv of CRITICAL_INVARIANTS) {
    const code = searchFiles(libFiles, inv.codeTerms);
    const test = searchFiles(testFiles, inv.testTerms);
    const formal = searchFiles(formalFiles, inv.formalTerms);
    const doc = searchFiles(docFiles, inv.docTerms);

    const layers = [
      { name: 'Code', result: code },
      { name: 'Test', result: test },
      { name: 'Formal', result: formal },
      { name: 'Docs', result: doc },
    ];

    const missing = layers.filter(function (l) { return !l.result.found; });
    const status = missing.length === 0 ? 'PASS' : 'FAIL';

    if (missing.length > 0) {
      failures++;
    }

    results.push({ inv: inv, layers: layers, status: status, missing: missing });
  }

  // Print coverage matrix
  console.log('Coverage Matrix:');
  console.log('-'.repeat(78));
  console.log(
    padRight('ID', 6) +
    padRight('Invariant', 38) +
    padRight('Code', 7) +
    padRight('Test', 7) +
    padRight('Formal', 8) +
    padRight('Docs', 7) +
    'Status'
  );
  console.log('-'.repeat(78));

  for (var i = 0; i < results.length; i++) {
    var r = results[i];
    var code = r.layers[0].result.found ? 'Y' : 'N';
    var test = r.layers[1].result.found ? 'Y' : 'N';
    var formal = r.layers[2].result.found ? 'Y' : 'N';
    var doc = r.layers[3].result.found ? 'Y' : 'N';

    console.log(
      padRight(r.inv.id, 6) +
      padRight(truncate(r.inv.name, 36), 38) +
      padRight(code, 7) +
      padRight(test, 7) +
      padRight(formal, 8) +
      padRight(doc, 7) +
      r.status
    );
  }

  console.log('-'.repeat(78));
  console.log('');

  // Print details for failures
  if (failures > 0) {
    console.log('FAILURES:');
    console.log('');
    for (var j = 0; j < results.length; j++) {
      var r2 = results[j];
      if (r2.status === 'FAIL') {
        console.log('  ' + r2.inv.id + ': ' + r2.inv.name);
        for (var k = 0; k < r2.missing.length; k++) {
          var m = r2.missing[k];
          var terms = getTerms(r2.inv, m.name);
          console.log('    - Missing ' + m.name + ' coverage');
          console.log('      Searched for terms: ' + terms.join(', '));
        }
        console.log('');
      }
    }
  }

  // Print pass details
  var passCount = 0;
  for (var p = 0; p < results.length; p++) {
    if (results[p].status === 'PASS') passCount++;
  }
  if (passCount > 0) {
    console.log('Passed: ' + passCount + '/' + results.length + ' invariants fully covered');
    for (var q = 0; q < results.length; q++) {
      var r3 = results[q];
      if (r3.status === 'PASS') {
        var codeFile = r3.layers[0].result.file || '?';
        var testFile = r3.layers[1].result.file || '?';
        var formalFile = r3.layers[2].result.file || '?';
        var docFile = r3.layers[3].result.file || '?';
        console.log('  ' + r3.inv.id + ': code=' + codeFile + ', test=' + testFile + ', formal=' + formalFile + ', docs=' + docFile);
      }
    }
  }

  console.log('');
  console.log('='.repeat(78));

  if (failures > 0) {
    console.log('RESULT: FAIL -- ' + failures + ' invariant(s) missing coverage layers');
    console.log('CI should block merge until all critical invariants have full coverage.');
    console.log('='.repeat(78));
    process.exit(1);
  } else {
    console.log('RESULT: PASS -- all ' + results.length + ' critical invariants fully covered');
    console.log('='.repeat(78));
    process.exit(0);
  }
}

function getTerms(inv, layerName) {
  switch (layerName) {
    case 'Code': return inv.codeTerms;
    case 'Test': return inv.testTerms;
    case 'Formal': return inv.formalTerms;
    case 'Docs': return inv.docTerms;
    default: return [];
  }
}

function padRight(str, len) {
  return (str + ' '.repeat(len)).slice(0, len);
}

function truncate(str, len) {
  return str.length > len ? str.slice(0, len - 2) + '..' : str;
}

main();
