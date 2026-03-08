// ============================================================
// Vigile GitHub Action — MCP & Agent Skill Security Scanner
// ============================================================
// Runs vigile-scan in CI/CD pipelines to catch tool poisoning,
// data exfiltration, and other AI agent security issues before
// they reach production.
//
// Inputs:  api-key, fail-on, scan-paths, upload-results
// Outputs: trust-score, trust-level, findings-count, critical-count, high-count

import * as core from '@actions/core';
import * as glob from '@actions/glob';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';

const execAsync = promisify(exec);

// ── Types matching vigile-scan's JSON output ──

interface Finding {
  id: string;
  severity: string;
  title: string;
  description: string;
  category: string;
  evidence?: string;
  recommendation: string;
}

interface ScanResult {
  server: { name: string; source: string; command: string; configPath: string };
  trustScore: number;
  trustLevel: string;
  findings: Finding[];
  scannedAt: string;
}

interface SkillScanResult {
  skill: { name: string; source: string; filePath: string; fileType: string };
  trustScore: number;
  trustLevel: string;
  findings: Finding[];
  scannedAt: string;
}

interface ScanSummary {
  totalServers: number;
  totalSkills: number;
  byTrustLevel: Record<string, number>;
  bySeverity: Record<string, number>;
  results: ScanResult[];
  skillResults: SkillScanResult[];
  timestamp: string;
  version: string;
}

// Ordered from most to least severe
const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'] as const;
type Severity = (typeof SEVERITY_LEVELS)[number];

// ── Main ──

async function run(): Promise<void> {
  try {
    // Read action inputs
    const apiKey = core.getInput('api-key');
    const failOn = core.getInput('fail-on') || 'critical';
    const scanPaths = core.getInput('scan-paths');
    const uploadResults = core.getInput('upload-results') !== 'false';

    // Validate fail-on severity
    if (!SEVERITY_LEVELS.includes(failOn as Severity)) {
      throw new Error(
        `Invalid fail-on severity: "${failOn}". ` +
          `Must be one of: ${SEVERITY_LEVELS.join(', ')}`,
      );
    }

    core.info('Vigile AI Security Scan');
    core.info('='.repeat(40));

    // Build the vigile-scan command
    const args = buildScanArgs({ scanPaths, uploadResults, apiKey });

    // Set API key in environment if provided
    const env: Record<string, string> = { ...process.env } as Record<string, string>;
    if (apiKey) {
      env.VIGILE_API_KEY = apiKey;
    }

    core.info(`Running: npx ${args.join(' ')}`);
    core.info('');

    // Execute vigile-scan
    const stdout = await runScan(args, env);

    // Parse JSON output
    const summary = parseOutput(stdout);

    // Calculate aggregate trust score
    const allResults = [...summary.results, ...summary.skillResults];
    const avgScore =
      allResults.length > 0
        ? Math.round(
            allResults.reduce((sum, r) => sum + r.trustScore, 0) / allResults.length,
          )
        : 100;

    // Derive trust level from score (same thresholds as vigile-scan)
    const trustLevel =
      avgScore >= 80
        ? 'trusted'
        : avgScore >= 60
          ? 'caution'
          : avgScore >= 40
            ? 'risky'
            : 'dangerous';

    // Count findings by severity
    const totalFindings = Object.values(summary.bySeverity).reduce((a, b) => a + b, 0);
    const criticalCount = summary.bySeverity['critical'] || 0;
    const highCount = summary.bySeverity['high'] || 0;

    // ── Set action outputs ──
    core.setOutput('trust-score', avgScore.toString());
    core.setOutput('trust-level', trustLevel);
    core.setOutput('findings-count', totalFindings.toString());
    core.setOutput('critical-count', criticalCount.toString());
    core.setOutput('high-count', highCount.toString());

    // ── Log summary ──
    logSummary(summary, avgScore, trustLevel, totalFindings, criticalCount, highCount);

    // ── Create annotations for individual findings ──
    annotateFindings(summary);

    // ── Apply fail-on threshold ──
    const failThresholdIdx = SEVERITY_LEVELS.indexOf(failOn as Severity);
    const failingSeverities = SEVERITY_LEVELS.slice(0, failThresholdIdx + 1);
    const failingCount = failingSeverities.reduce(
      (count, sev) => count + (summary.bySeverity[sev] || 0),
      0,
    );

    if (failingCount > 0) {
      core.setFailed(
        `Found ${failingCount} finding(s) at severity "${failOn}" or above. ` +
          `Trust score: ${avgScore}/100 (${trustLevel})`,
      );
    } else {
      core.info('');
      core.info(`No findings at "${failOn}" severity or above — check passed`);
    }
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed('An unexpected error occurred');
    }
  }
}

// ── Helpers ──

/**
 * Build the vigile-scan CLI arguments.
 *
 * - Always uses --json for machine-readable output
 * - Always uses --all to scan both MCP servers and skills
 * - Respects scan-paths (comma-separated config file paths)
 * - Respects upload-results preference
 */
function buildScanArgs(opts: {
  scanPaths: string;
  uploadResults: boolean;
  apiKey: string;
}): string[] {
  const args = ['vigile-scan', '--json', '--all'];

  // If specific scan paths provided, use the first one as --config
  // (vigile-scan --config takes a single path)
  if (opts.scanPaths) {
    const paths = opts.scanPaths
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean);
    if (paths.length > 0) {
      args.push('--config', paths[0]);
      if (paths.length > 1) {
        core.warning(
          `scan-paths contains ${paths.length} paths but vigile-scan --config ` +
            `accepts one path. Using: ${paths[0]}. ` +
            `Other paths will be discovered automatically.`,
        );
      }
    }
  }

  // Skip upload if no API key or explicitly disabled
  if (!opts.uploadResults || !opts.apiKey) {
    args.push('--no-upload');
  }

  return args;
}

/**
 * Run vigile-scan via npx and return stdout.
 *
 * vigile-scan may exit non-zero when findings are present,
 * so we capture stdout from the error object in that case.
 */
async function runScan(
  args: string[],
  env: Record<string, string>,
): Promise<string> {
  try {
    const { stdout } = await execAsync(`npx ${args.join(' ')}`, {
      env,
      maxBuffer: 10 * 1024 * 1024, // 10 MB
      timeout: 300_000, // 5 minutes
    });
    return stdout;
  } catch (error: unknown) {
    // vigile-scan exits non-zero when findings exceed threshold —
    // the JSON output is still valid on stdout
    const execError = error as { stdout?: string; stderr?: string; message?: string };
    if (execError.stdout) {
      return execError.stdout;
    }
    const stderr = execError.stderr || '';
    const msg = execError.message || 'Unknown error';
    throw new Error(
      `vigile-scan failed to execute.\n` +
        `Error: ${msg}\n` +
        (stderr ? `Stderr: ${stderr.substring(0, 500)}` : ''),
    );
  }
}

/**
 * Parse vigile-scan's JSON output into a ScanSummary.
 * Handles cases where non-JSON lines precede the JSON
 * (e.g., npx download messages).
 */
function parseOutput(stdout: string): ScanSummary {
  // Try parsing the full output first
  const trimmed = stdout.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    // npx may print download/install messages before the JSON.
    // Find the first '{' that starts the JSON object.
    const jsonStart = trimmed.indexOf('{');
    if (jsonStart > 0) {
      try {
        return JSON.parse(trimmed.substring(jsonStart));
      } catch {
        // fall through
      }
    }
    core.error('Failed to parse vigile-scan output as JSON');
    core.error(`Raw output (first 500 chars): ${trimmed.substring(0, 500)}`);
    throw new Error('vigile-scan did not produce valid JSON output');
  }
}

/**
 * Log a formatted summary to the GitHub Actions console.
 */
function logSummary(
  summary: ScanSummary,
  avgScore: number,
  trustLevel: string,
  totalFindings: number,
  criticalCount: number,
  highCount: number,
): void {
  core.info('Scan Complete');
  core.info('-'.repeat(40));
  core.info(`  Trust Score:  ${avgScore}/100 (${trustLevel})`);
  core.info(`  Servers:      ${summary.totalServers}`);
  core.info(`  Skills:       ${summary.totalSkills}`);
  core.info(`  Findings:     ${totalFindings} total`);

  if (criticalCount > 0) core.error(`  Critical:     ${criticalCount}`);
  if (highCount > 0) core.warning(`  High:         ${highCount}`);

  const mediumCount = summary.bySeverity['medium'] || 0;
  const lowCount = summary.bySeverity['low'] || 0;
  if (mediumCount > 0) core.info(`  Medium:       ${mediumCount}`);
  if (lowCount > 0) core.info(`  Low:          ${lowCount}`);

  core.info('-'.repeat(40));
}

/**
 * Create GitHub annotations (error/warning/notice) for each finding.
 * Critical findings appear as errors, high as warnings, others as notices.
 */
function annotateFindings(summary: ScanSummary): void {
  for (const result of summary.results) {
    for (const finding of result.findings) {
      const msg = `[${finding.id}] ${finding.title} in "${result.server.name}" (${result.server.source})`;
      emitAnnotation(finding.severity, msg);
    }
  }

  for (const result of summary.skillResults) {
    for (const finding of result.findings) {
      const msg = `[${finding.id}] ${finding.title} in "${result.skill.name}" (${result.skill.fileType})`;
      emitAnnotation(finding.severity, msg);
    }
  }
}

/**
 * Emit a GitHub annotation at the appropriate severity level.
 */
function emitAnnotation(severity: string, message: string): void {
  switch (severity) {
    case 'critical':
      core.error(message);
      break;
    case 'high':
      core.warning(message);
      break;
    default:
      core.notice(message);
      break;
  }
}

// ── Entry point ──
run();
