import { newOBuildHooks } from '@kagal/build-tsdoc';
import { copyFileSync } from 'node:fs';
import { defineBuildConfig } from 'obuild/config';

const tsdoc = newOBuildHooks();

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
    entries: tsdoc.entries,
    end(context) {
      tsdoc.end(context);
      emitLegacyDTS();
    },
  },
});
