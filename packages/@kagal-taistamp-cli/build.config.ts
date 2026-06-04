import { defineBuildConfig } from 'obuild/config';

export default defineBuildConfig({
  entries: [
    { type: 'bundle', input: ['./src/bin.ts'] },
  ],
  hooks: {
    rolldownOutput(outConfig) {
      outConfig.sourcemap = true;
    },
  },
});
