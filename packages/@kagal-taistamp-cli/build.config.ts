import { newOBuildHooks } from '@kagal/build-tsdoc';
import { defineBuildConfig } from 'obuild/config';

const tsdoc = newOBuildHooks();

export default defineBuildConfig({
  entries: [
    { type: 'bundle', input: ['./src/bin.ts'] },
  ],
  hooks: {
    rolldownOutput(outConfig) {
      outConfig.sourcemap = true;
    },
    entries: tsdoc.entries,
    end: tsdoc.end,
  },
});
