// KeyConfig ↔ TaistampHandlerConfig field compatibility
//
// Compile-time only — these `expectTypeOf` calls
// produce no runtime output; the file is type-checked
// via tsconfig.tests.json but never executed by vitest
// (not a `*.test.ts` file). The vitest entry point is
// the only runtime import; everything else is
// `import type`.
//
// Lives on the @kagal/taistamp side because taistamp
// depends on @kagal/ed25519-secret (not the reverse),
// so this is the only package where both types are
// visible without a circular dependency.

import type { KeyConfig } from '@kagal/ed25519-secret';
import { expectTypeOf } from 'vitest';

import type { TaistampHandlerConfig } from '..';

// The two fields TaistampHandlerConfig consumes from a
// KeyConfig must remain assignable into the handler's
// slots. KeyConfig's `selector` and `signer` are
// required; the handler's are optional, so a one-way
// fit is the right invariant — branding KeyConfig's
// fields with a narrower type would still pass, but a
// shape change (different `Signer` signature, a number
// `selector`, etc.) would fire.
expectTypeOf<
  KeyConfig['selector']
>().toExtend<TaistampHandlerConfig['selector']>();
expectTypeOf<
  KeyConfig['signer']
>().toExtend<TaistampHandlerConfig['signer']>();
