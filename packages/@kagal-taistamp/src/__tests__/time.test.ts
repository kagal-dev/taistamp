import { describe, expect, it } from 'vitest';

import {
  fromUTC,
  now,
  tai64nLabel,
  tai64nLabelFromUTC,
} from '../utils';

describe('fromUTC', () => {
  it('applies the current leap-second offset', () => {
    expect(fromUTC(0)).toEqual({ sec: 37, nano: 0, offset: 37 });
  });

  it('scales sub-second milliseconds to nanoseconds', () => {
    expect(fromUTC(1)).toEqual({ sec: 37, nano: 1_000_000, offset: 37 });
    expect(fromUTC(1500))
      .toEqual({ sec: 38, nano: 500_000_000, offset: 37 });
  });

  it('floors whole seconds', () => {
    expect(fromUTC(999)).toEqual({ sec: 37, nano: 999_000_000, offset: 37 });
    expect(fromUTC(1000)).toEqual({ sec: 38, nano: 0, offset: 37 });
  });
});

describe('now', () => {
  it('matches the fromUTC shape', () => {
    const value = now();
    expect(value.offset).toBe(37);
    expect(Number.isInteger(value.sec)).toBe(true);
    expect(Number.isInteger(value.nano)).toBe(true);
    expect(value.nano).toBeGreaterThanOrEqual(0);
    expect(value.nano).toBeLessThan(1_000_000_000);
    // TAI for 2026 onwards sits past the 2026-01-01 UTC second
    expect(value.sec).toBeGreaterThan(1_767_225_600);
  });
});

describe('tai64nLabel', () => {
  it('folds seconds onto the TAI64 epoch', () => {
    expect(tai64nLabel({ sec: 0, nano: 0 }))
      .toBe('@400000000000000000000000');
    expect(tai64nLabel({ sec: 37, nano: 0 }))
      .toBe('@400000000000002500000000');
  });

  it('splits seconds beyond 32 bits into the high word', () => {
    expect(tai64nLabel({ sec: 0x1_23_45_67_89, nano: 0 }))
      .toBe('@400000012345678900000000');
  });

  it('zero-pads the nanosecond field', () => {
    expect(tai64nLabel({ sec: 0, nano: 0x12_34 }))
      .toBe('@400000000000000000001234');
  });

  it('defaults to the current time', () => {
    expect(tai64nLabel()).toMatch(/^@[\da-f]{24}$/);
  });
});

describe('tai64nLabelFromUTC', () => {
  it('labels the UTC epoch with the leap offset applied', () => {
    expect(tai64nLabelFromUTC(0)).toBe('@400000000000002500000000');
  });

  it('matches tai64nLabel over fromUTC', () => {
    expect(tai64nLabelFromUTC(1500)).toBe(tai64nLabel(fromUTC(1500)));
  });
});
