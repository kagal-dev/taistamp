import { copyFileSync } from 'node:fs';
import { type BuildConfig, defineBuildConfig } from 'obuild/config';

type BuildContext = Parameters<
  NonNullable<NonNullable<BuildConfig['hooks']>['end']>
>[0];

function extractDocumentation(context: BuildContext): void {
  // TODO: replace with a real TSDoc extractor.
  console.warn(`[${context.pkg.name}] TSDoc extraction not run`);
}

/**
 * Emits `dist/index.d.ts` as a byte-identical
 * companion of `dist/index.d.mts`, so legacy
 * declaration extractors (e.g. jsDocs.io) that
 * probe for the `.d.ts` extension can find the
 * types.
 *
 * Modern `moduleResolution` (`node16` / `nodenext` /
 * `bundler`) resolves `.d.mts` via the `exports`
 * field; legacy ones don't.
 */
function emitLegacyDTS(): void {
  copyFileSync('dist/index.d.mts', 'dist/index.d.ts');
}

export default defineBuildConfig({
  entries: [
    { type: 'bundle', input: ['./src/index.ts'] },
  ],
  hooks: {
    rolldownOutput(outConfig) {
      outConfig.sourcemap = true;
    },
    end(context) {
      extractDocumentation(context);
      emitLegacyDTS();
    },
  },
});
