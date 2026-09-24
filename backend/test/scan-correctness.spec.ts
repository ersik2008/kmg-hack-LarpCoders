import { describe, it, expect, vi } from 'vitest';
import { PolicyService, ScannerStatusRecord } from '../src/policy/policy.service.js';
import { GraphService } from '../src/graph/graph.service.js';
import { RepositoryService } from '../src/repository/repository.service.js';
import { Finding } from '../src/generated/prisma/client.js';
import * as crypto from 'crypto';

const TEST_ENCRYPTION_KEY = '12345678901234567890123456789012';

/** Mirrors AuthService.encrypt so mocked accounts hold a decryptable token. */
function encryptForTest(text: string): string {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(TEST_ENCRYPTION_KEY), iv);
  const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

describe('KMG Security Platform — Mandatory Verification Suite', () => {
  // PolicyService reads the stored gate configuration from the database; these
  // tests exercise evaluate() with explicit inputs, so a stub is enough.
  const prismaStub: any = { policy: { findFirst: vi.fn(), create: vi.fn(), update: vi.fn() } };
  const policyService = new PolicyService(prismaStub);

  const createCompletedScanners = (): Record<string, ScannerStatusRecord> => ({
    semgrep: { status: 'COMPLETED', findingsCount: 0, error: null },
    gitleaks: { status: 'COMPLETED', findingsCount: 0, error: null },
    trivy: { status: 'COMPLETED', findingsCount: 0, error: null },
  });

  // TEST 1: Valid repo, 0 findings, all scanners completed => PASS permissible
  it('TEST 1: should return PASS when valid repo has 0 findings and all scanners completed', () => {
    const input = {
      findings: [] as Finding[],
      scanners: createCompletedScanners(),
      repositoryStatus: 'READY' as const,
    };

    const res = policyService.evaluate(input);
    expect(res.isPass).toBe(true);
    expect(res.result).toBe('PASS');
    expect(res.riskScore).toBe(0);
    expect(res.isIncomplete).toBe(false);
  });

  // TEST 2: Valid repo, SQL injection finding => PASS impossible (BLOCK or REVIEW)
  it('TEST 2: should return BLOCK or REVIEW (never PASS) when SQL injection finding exists', () => {
    const sqlInjectionFinding: Finding = {
      id: 'f-sql-1',
      scanId: 'scan-1',
      scanner: 'semgrep',
      ruleId: 'javascript.express.security.audit.raw-query',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      title: 'SQL Injection via string interpolation in raw query',
      description: 'Untrusted user input concatenated to db.query',
      filePath: 'src/user.service.ts',
      startLine: 42,
      endLine: 42,
      codeSnippet: 'await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);',
      category: 'injection',
      metadata: null,
      createdAt: new Date(),
    };

    const input = {
      findings: [sqlInjectionFinding],
      scanners: {
        semgrep: { status: 'COMPLETED' as const, findingsCount: 1, error: null },
        gitleaks: { status: 'COMPLETED' as const, findingsCount: 0, error: null },
        trivy: { status: 'COMPLETED' as const, findingsCount: 0, error: null },
      },
      repositoryStatus: 'READY' as const,
    };

    const res = policyService.evaluate(input);
    expect(res.isPass).toBe(false);
    expect(res.result).toBe('BLOCK');
    expect(res.riskScore).toBeGreaterThanOrEqual(7.0);
  });

  // TEST 3: Semgrep failed, 0 findings from other scanners => PASS forbidden
  it('TEST 3: should forbid PASS and mark scan as PARTIAL/INCOMPLETE if Semgrep failed', () => {
    const scanners = createCompletedScanners();
    scanners.semgrep = { status: 'FAILED', findingsCount: 0, error: 'Semgrep CLI timeout or syntax crash' };

    const input = {
      findings: [] as Finding[],
      scanners,
      repositoryStatus: 'READY' as const,
    };

    const res = policyService.evaluate(input);
    expect(res.isPass).toBe(false);
    expect(res.result).toBeNull();
    expect(res.isIncomplete).toBe(true);
    expect(res.statusText).toBe('SCAN_PARTIAL');
    expect(res.reasons.some(r => r.includes('semgrep'))).toBe(true);
  });

  // TEST 4: Gitleaks failed => PASS forbidden
  it('TEST 4: should forbid PASS if Gitleaks failed', () => {
    const scanners = createCompletedScanners();
    scanners.gitleaks = { status: 'FAILED', findingsCount: 0, error: 'Gitleaks process exited with code 2' };

    const input = {
      findings: [] as Finding[],
      scanners,
      repositoryStatus: 'READY' as const,
    };

    const res = policyService.evaluate(input);
    expect(res.isPass).toBe(false);
    expect(res.result).toBeNull();
    expect(res.isIncomplete).toBe(true);
    expect(res.reasons.some(r => r.includes('gitleaks'))).toBe(true);
  });

  // TEST 5: Trivy failed => PASS forbidden
  it('TEST 5: should forbid PASS if Trivy failed', () => {
    const scanners = createCompletedScanners();
    scanners.trivy = { status: 'FAILED', findingsCount: 0, error: 'Trivy database download failed' };

    const input = {
      findings: [] as Finding[],
      scanners,
      repositoryStatus: 'READY' as const,
    };

    const res = policyService.evaluate(input);
    expect(res.isPass).toBe(false);
    expect(res.result).toBeNull();
    expect(res.isIncomplete).toBe(true);
    expect(res.reasons.some(r => r.includes('trivy'))).toBe(true);
  });

  // TEST 6: Repository clone failed => FAILED/INCOMPLETE
  it('TEST 6: should forbid PASS and mark INCOMPLETE if repository status is not READY', () => {
    const input = {
      findings: [] as Finding[],
      scanners: createCompletedScanners(),
      repositoryStatus: 'FAILED' as const,
    };

    const res = policyService.evaluate(input);
    expect(res.isPass).toBe(false);
    expect(res.result).toBeNull();
    expect(res.isIncomplete).toBe(true);
    expect(res.statusText).toBe('SCAN_INCOMPLETE');
  });

  // TEST 7: Invalid scanner JSON / crash => FAILED/PARTIAL
  it('TEST 7: should reject PASS if scanner status is INVALID', () => {
    const scanners = createCompletedScanners();
    scanners.semgrep = { status: 'INVALID', findingsCount: 0, error: 'Failed to parse JSON output' };

    const input = {
      findings: [] as Finding[],
      scanners,
      repositoryStatus: 'READY' as const,
    };

    const res = policyService.evaluate(input);
    expect(res.isPass).toBe(false);
    expect(res.result).toBeNull();
    expect(res.isIncomplete).toBe(true);
  });

  // TEST 8: Groq failed, valid scanner findings => security result preserved
  it('TEST 8: should preserve deterministic findings and calculate verdict even if AI failed', () => {
    const findings: Finding[] = [
      {
        id: 'f-secret-1',
        scanId: 'scan-1',
        scanner: 'gitleaks',
        ruleId: 'aws-access-key',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        title: 'Exposed AWS Access Key',
        description: 'Hardcoded key detected',
        filePath: 'config/aws.ts',
        startLine: 5,
        endLine: 5,
        codeSnippet: 'const key = "AKIA1234567890123456";',
        category: 'secret',
        metadata: null,
        createdAt: new Date(),
      }
    ];

    const input = {
      findings,
      scanners: {
        semgrep: { status: 'COMPLETED' as const, findingsCount: 0, error: null },
        gitleaks: { status: 'COMPLETED' as const, findingsCount: 1, error: null },
        trivy: { status: 'COMPLETED' as const, findingsCount: 0, error: null },
      },
      repositoryStatus: 'READY' as const,
    };

    // PolicyEngine computes deterministic verdict regardless of AI availability
    const res = policyService.evaluate(input);
    expect(res.isBlocked).toBe(true);
    expect(res.result).toBe('BLOCK');
    expect(res.riskScore).toBe(10);
  });

  // TEST 9: 0 findings, AI unavailable => valid deterministic result completes with PASS
  it('TEST 9: should permit PASS when 0 findings and scanners completed, even if AI was unavailable', () => {
    const input = {
      findings: [] as Finding[],
      scanners: createCompletedScanners(),
      repositoryStatus: 'READY' as const,
    };

    const res = policyService.evaluate(input);
    expect(res.isPass).toBe(true);
    expect(res.result).toBe('PASS');
    expect(res.riskScore).toBe(0);
  });

  // TEST 10: Finding without source->sink evidence => POTENTIAL attack path, not CONFIRMED
  it('TEST 10: should mark relationship as POTENTIAL when direct user-controlled input cannot be proven in code', async () => {
    const prismaMock: any = {
      finding: {
        findMany: vi.fn().mockResolvedValue([
          {
            id: 'f-1',
            scanId: 'scan-x',
            scanner: 'semgrep',
            severity: 'HIGH',
            confidence: 'HIGH',
            title: 'Potential SQL Injection',
            filePath: 'src/db.ts',
            startLine: 20,
            codeSnippet: 'return database.execute(queryString);', // No req.query or user input in this snippet
            createdAt: new Date()
          }
        ])
      },
      graphEdge: {
        findMany: vi.fn().mockResolvedValue([])
      }
    };

    const graphService = new GraphService(prismaMock);
    const graphData = await graphService.getGraphData('scan-x');

    expect(graphData.hasFindings).toBe(true);
    // Source node should be marked POTENTIAL
    const sourceNode = graphData.nodes.find(n => n.data?.type === 'SOURCE');
    expect(sourceNode).toBeDefined();
    expect(sourceNode?.data?.confidence).toBe('POTENTIAL');

    // Edges should also reflect POTENTIAL
    const flowEdge = graphData.edges.find(e => e.type === 'FLOWS_TO');
    expect(flowEdge).toBeDefined();
    expect(flowEdge?.data?.confidence).toBe('POTENTIAL');
  });

  // TEST 11: Confirmed source->sink relationship => graph relationship with code evidence
  it('TEST 11: should mark relationship as CONFIRMED when user input is observed in code snippet', async () => {
    const prismaMock: any = {
      finding: {
        findMany: vi.fn().mockResolvedValue([
          {
            id: 'f-2',
            scanId: 'scan-y',
            scanner: 'semgrep',
            severity: 'CRITICAL',
            confidence: 'HIGH',
            title: 'SQL Injection',
            filePath: 'src/controllers/auth.controller.ts',
            startLine: 35,
            codeSnippet: 'const userId = req.query.id;\nconst q = `SELECT * FROM users WHERE id = ${userId}`;\nawait db.query(q);',
            createdAt: new Date()
          }
        ])
      },
      graphEdge: {
        findMany: vi.fn().mockResolvedValue([])
      }
    };

    const graphService = new GraphService(prismaMock);
    const graphData = await graphService.getGraphData('scan-y');

    expect(graphData.hasFindings).toBe(true);
    const sourceNode = graphData.nodes.find(n => n.data?.type === 'SOURCE');
    expect(sourceNode?.data?.confidence).toBe('CONFIRMED');

    const flowEdge = graphData.edges.find(e => e.type === 'FLOWS_TO');
    expect(flowEdge?.data?.confidence).toBe('CONFIRMED');
  });

  // TEST 12: Normal GitHub repository => uses real repository files, no test-corpus override
  it('TEST 12: should not substitute local security test corpus for normal GitHub repositories', async () => {
    const prismaMock: any = {
      repository: {
        findUnique: vi.fn().mockResolvedValue({
          id: 'repo-normal-1',
          name: 'my-security-test-app', // contains "security-test" in name!
          fullName: 'org/my-security-test-app',
          defaultBranch: 'main'
        })
      },
      gitHubAccount: {
        findUnique: vi.fn().mockResolvedValue({
          userId: 'user-1',
          accessTokenHash: encryptForTest('gho_test_token'),
        })
      }
    };

    const configMock: any = {
      get: vi.fn().mockImplementation((key: string) => {
        if (key === 'ENCRYPTION_KEY') return TEST_ENCRYPTION_KEY;
        return null;
      })
    };

    const githubMock: any = {};

    const repoService = new RepositoryService(prismaMock, configMock, githubMock);
    vi.spyOn(repoService, 'runCommand').mockRejectedValue(new Error('fatal: remote repository not found'));

    // In normal mode (isTestMode = false), if git clone fails, it throws immediately
    // rather than quietly succeeding with local security test corpus!
    await expect(
      repoService.cloneRepositoryWithMeta('user-1', 'repo-normal-1', 'scan-1', 'main', false)
    ).rejects.toThrow(/Failed to clone repository/);
  });

  // TEST 13: A revoked/absent GitHub authorization must stop the scan up front,
  // never fall back to an anonymous clone or to local fixtures.
  it('TEST 13: should refuse to clone when the GitHub authorization was revoked by logout', async () => {
    const prismaMock: any = {
      repository: {
        findUnique: vi.fn().mockResolvedValue({
          id: 'repo-normal-2',
          name: 'app',
          fullName: 'org/app',
          defaultBranch: 'main'
        })
      },
      gitHubAccount: {
        // logout wipes the stored token
        findUnique: vi.fn().mockResolvedValue({ userId: 'user-1', accessTokenHash: '' })
      }
    };

    const configMock: any = {
      get: vi.fn().mockImplementation((key: string) => {
        if (key === 'ENCRYPTION_KEY') return TEST_ENCRYPTION_KEY;
        return null;
      })
    };

    const repoService = new RepositoryService(prismaMock, configMock, {} as any);
    const runCommand = vi.spyOn(repoService, 'runCommand').mockResolvedValue({ stdout: '', stderr: '' });

    await expect(
      repoService.cloneRepositoryWithMeta('user-1', 'repo-normal-2', 'scan-2', 'main', false)
    ).rejects.toThrow(/No valid GitHub authorization/);

    expect(runCommand).not.toHaveBeenCalled();
  });
});
