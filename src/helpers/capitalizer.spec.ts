import Capitalize from './capitalizer';

describe('capitalize', () => {
  it('should capitalize the first letter of a string', () => {
    expect(Capitalize('hello')).toBe('Hello');
  })
});