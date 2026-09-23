/**
 * Capture the JS SDK's content-identity WIRE payloads as test fixtures.
 *
 * Runs the SDK's own builders (src/identity/run-identity.ts prepareContentIdentityRun
 * -> sessionWire / trialWire, and src/identity/observed-providers.ts for provider
 * observations) -- nothing here assembles a wire object by hand -- and writes
 * tests/data/content_identity_wire/js_sdk.json.
 *
 * Usage, from a traigent-js checkout that has src/identity/run-identity.ts:
 *
 *   cd <traigent-js checkout> && npx tsx <TraigentSchema>/scripts/content_identity_wire/capture_js.mts .
 *
 * Keys are the PUBLIC TEST purpose keys of vector tenant_a
 * (traigent_schema/data/content_identity_v1_vectors.json key_derivation), installed
 * through the SDK's production entry point ContentIdentityKeys.fromPurposeKeys.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const schemaRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const sdkRoot = resolve(process.argv[2] ?? '.');
const out = resolve(schemaRoot, 'tests', 'data', 'content_identity_wire', 'js_sdk.json');

const load = async (rel: string): Promise<any> => import(pathToFileURL(resolve(sdkRoot, rel)).href);

function git(...args: string[]): string {
  return execFileSync('git', ['-C', sdkRoot, ...args], { encoding: 'utf8' }).trim();
}

function declaredReasons(): string[] {
  const text = readFileSync(resolve(sdkRoot, 'src', 'identity', 'run-identity.ts'), 'utf8');
  const union = /export type ContentIdentityUnavailableReason =([^;]*);/.exec(text);
  if (union === null) {
    throw new Error('ContentIdentityUnavailableReason union not found');
  }
  return [...union[1]!.matchAll(/'([a-z_]+)'/g)].map((match) => match[1]!).sort();
}

const main = async (): Promise<void> => {
  const ci = await load('src/identity/content-identity.ts');
  const ri = await load('src/identity/run-identity.ts');
  const op = await load('src/identity/observed-providers.ts');

  const vectors = JSON.parse(
    readFileSync(resolve(schemaRoot, 'traigent_schema', 'data', 'content_identity_v1_vectors.json'), 'utf8')
  );
  const row = vectors.key_derivation.find((k: any) => k.tenant === 'tenant_a');
  const grant = {
    tenant_id: row.tenant_id,
    kid: row.key_id,
    example_id_key: row.example_id_key_hex,
    example_version_key: row.example_version_key_hex,
    encoding: 'hex',
  };
  const keyProvider = () =>
    ci.ContentIdentityKeys.fromPurposeKeys({
      tenantId: grant.tenant_id,
      keyId: grant.kid,
      exampleIdKey: grant.example_id_key,
      exampleVersionKey: grant.example_version_key,
    });

  const readers = {
    readInputAndExpected: (r: any) => ({ input: r.input, expected: r.output }),
  };
  const agent = (q: string): string => q;
  const exact = (output: unknown, expected: unknown): number => (output === expected ? 1 : 0);
  const objectives = [{ metric: 'accuracy', direction: 'maximize', weight: 1 }];
  const rows = [
    { input: { q: 'a' }, output: '1' },
    { input: { q: 'b' }, output: '2' },
    { input: { q: 'a' }, output: '1' },
    { input: { q: 'c' }, output: '3' },
    { input: { q: 'c' }, output: '4' },
  ];

  const prepare = (overrides: Record<string, unknown> = {}): Promise<any> =>
    ri.prepareContentIdentityRun({
      options: { keyProvider },
      agentName: 'agent_1',
      agentFunction: agent,
      defaultConfig: {},
      rows,
      readers,
      evaluatorFunctions: [],
      objectives,
      ...overrides,
    });

  process.removeAllListeners('warning');
  process.on('warning', () => undefined);

  const session: Record<string, unknown> = {};
  const trial: Record<string, unknown> = {};

  const full = await prepare();
  session['all_slots_builtin_evaluator'] = full.sessionWire();
  session['declared_evaluator_with_judge'] = (
    await prepare({
      defaultConfig: { temperature: 0.2 },
      options: {
        keyProvider,
        evaluator: {
          evaluatorId: 'ev_exact',
          judge: { provider: 'openai', model: 'gpt-4o-mini', configDigest: 'sha256:' + 'b'.repeat(64) },
          configDigest: 'sha256:' + 'a'.repeat(64),
          helperDigests: {},
          dependencyVersions: { ragas: '0.2.1' },
        },
      },
      evaluatorFunctions: [{ label: 'metric:accuracy', fn: exact }],
    })
  ).sessionWire();
  session['fallback_agent_id'] = (
    await prepare({ agentName: undefined, agentKeyFallback: 'agent' })
  ).sessionWire();
  session['withheld_agent_evaluator_dataset'] = (
    await prepare({
      agentName: 'not a key!',
      rows: Array.from({ length: ri.MAX_INLINE_MEMBERS + 1 }, (_, n) => ({
        input: { q: `row ${n}` },
        output: String(n),
      })),
      evaluatorFunctions: [{ label: 'metric:accuracy', fn: exact }],
    })
  ).sessionWire();
  session['unidentifiable_dataset_bad_evaluator_id'] = (
    await prepare({
      rows: [{ input: { q: 'a' }, output: '1' }, { input: { n: 2 ** 53 }, output: 'x' }],
      options: { keyProvider, evaluator: { evaluatorId: 'bad id!' } },
    })
  ).sessionWire();
  session['rows_not_held'] = (await prepare({ rows: undefined })).sessionWire();

  const { observed } = await op.withObservedProviderVersions(() => {
    for (let n = 0; n < 3; n += 1) {
      op.recordObservedProviderVersion({
        provider: 'openai',
        requestedModel: 'gpt-4o',
        responseModel: 'gpt-4o-2024-08-06',
        systemFingerprint: 'fp_44709d6fcb',
      });
    }
    op.recordObservedProviderVersion({
      provider: 'anthropic',
      requestedModel: 'claude-sonnet-4-5',
      responseModel: undefined,
    });
  });
  trial['full_dataset_with_observations'] = full.trialWire(
    'trial_1',
    { temperature: 0.2 },
    [0, 1, 2, 3, 4],
    observed
  );
  trial['subset_no_observations'] = full.trialWire('trial_2', { temperature: 0.7 }, [0, 1], []);
  trial['config_not_canonicalizable'] = full.trialWire('trial_3', { a: () => 1 }, [0], []);
  trial['row_outside_dataset'] = full.trialWire('trial_4', {}, null, []);
  const unidentifiable = await prepare({
    agentName: 'not a key!',
    rows: [{ input: { n: 2 ** 53 }, output: 'x' }],
  });
  trial['unidentifiable_dataset_no_agent'] = unidentifiable.trialWire('trial_5', {}, [], []);

  mkdirSync(dirname(out), { recursive: true });
  const document = {
    note:
      'Generated by scripts/content_identity_wire/capture_js.mts from the SDK\'s own builders. ' +
      'Do not hand-edit; regenerate.',
    generated_by: {
      sdk: 'traigent-js',
      commit: git('rev-parse', 'HEAD'),
      dirty_paths: git('status', '--porcelain')
        .split('\n')
        .filter((line) => line.length > 0)
        .map((line) => line.slice(3))
        .sort(),
    },
    // The SDK's own declared reason vocabulary: the ContentIdentityUnavailableReason
    // union in src/identity/run-identity.ts (a type, so read from the source text).
    declared_reasons: declaredReasons(),
    purpose_key_grant: grant,
    session,
    trial,
  };
  writeFileSync(out, JSON.stringify(document, null, 2) + '\n', 'utf8');
  console.log(`wrote ${out} (${Object.keys(session).length} session, ${Object.keys(trial).length} trial payloads)`);
};

await main();
