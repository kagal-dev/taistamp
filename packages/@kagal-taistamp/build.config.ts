import { type BuildConfig, defineBuildConfig } from 'obuild/config';

type BuildContext = Parameters<
  NonNullable<NonNullable<BuildConfig['hooks']>['end']>
>[0];

function extractDocumentation(context: BuildContext): void {
  // TODO: replace with a real TSDoc extractor.
  console.warn(`[${context.pkg.name}] TSDoc extraction not run`);
}

export default defineBuildConfig({
  entries: [
    { type: 'bundle', input: ['./src/index.ts'] },
  ],
  hooks: {
    rolldownOutput(outConfig) {
      outConfig.sourcemap = true;
    },
    end: extractDocumentation,
  },
});
