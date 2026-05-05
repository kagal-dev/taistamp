import { TAI64_EPOCH_HI } from './const';
import { TAI_LEAP_SECONDS } from './leap-seconds';

type timestamp = {
  nano: number
  sec: number

  offset?: number
};

export const fromUTC = (utc: number): timestamp => {
  // TODO: leap seconds table
  const sec = Math.floor(utc / 1000) + TAI_LEAP_SECONDS;
  const nano = (utc % 1000) * 1e6;
  return { sec, nano, offset: TAI_LEAP_SECONDS };
};

export const now = (): timestamp => {
  const utc = Date.now();
  return fromUTC(utc);
};

export const tai64nLabel = (value?: timestamp): string => {
  const { sec, nano } = value ?? now();

  const secHi = Math.trunc(sec / u32Range) + TAI64_EPOCH_HI;
  const secLo = sec % u32Range;

  const secHiHex = secHi.toString(16).padStart(8, '0');
  const secLoHex = secLo.toString(16).padStart(8, '0');
  const nanoHex = nano.toString(16).padStart(8, '0');

  return `@${secHiHex}${secLoHex}${nanoHex}`;
};

export const tai64nLabelFromUTC = (utc: number): string => tai64nLabel(fromUTC(utc));

const u32Range = 0x1_00_00_00_00;
