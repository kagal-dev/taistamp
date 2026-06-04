#!/usr/bin/env node
import { runMain } from 'citty';
import { consola } from 'consola';

import { main } from './index';

// Pre-runMain setup window for global consola config.
consola.options.formatOptions.date = false;

runMain(main);
