/* globals describe, it, expect, StringStream, Type1Parser,
           SEAC_ANALYSIS_ENABLED */

'use strict';

describe('Type1Parser', function() {
  it('splits tokens', function() {
    var stream = new StringStream('/BlueValues[-17 0]noaccess def');
    var parser = new Type1Parser(stream, false, SEAC_ANALYSIS_ENABLED);
    expect(parser.getToken()).toEqual('/');
    expect(parser.getToken()).toEqual('BlueValues');
    expect(parser.getToken()).toEqual('[');
    expect(parser.getToken()).toEqual('-17');
    expect(parser.getToken()).toEqual('0');
    expect(parser.getToken()).toEqual(']');
    expect(parser.getToken()).toEqual('noaccess');
    expect(parser.getToken()).toEqual('def');
    expect(parser.getToken()).toEqual(null);
  });

  it('handles glued tokens', function() {
    var stream = new StringStream('dup/CharStrings');
    var parser = new Type1Parser(stream, false, SEAC_ANALYSIS_ENABLED);
    expect(parser.getToken()).toEqual('dup');
    expect(parser.getToken()).toEqual('/');
    expect(parser.getToken()).toEqual('CharStrings');
  });

  it('ignores whitespace', function() {
    var stream = new StringStream('\nab   c\t');
    var parser = new Type1Parser(stream, false, SEAC_ANALYSIS_ENABLED);
    expect(parser.getToken()).toEqual('ab');
    expect(parser.getToken()).toEqual('c');
  });

  it('parses numbers', function() {
    var stream = new StringStream('123');
    var parser = new Type1Parser(stream, false, SEAC_ANALYSIS_ENABLED);
    expect(parser.readNumber()).toEqual(123);
  });

  it('parses booleans', function() {
    var stream = new StringStream('true false');
    var parser = new Type1Parser(stream, false, SEAC_ANALYSIS_ENABLED);
    expect(parser.readBoolean()).toEqual(1);
    expect(parser.readBoolean()).toEqual(0);
  });

  it('parses number arrays', function() {
    var stream = new StringStream('[1 2]');
    var parser = new Type1Parser(stream, false, SEAC_ANALYSIS_ENABLED);
    expect(parser.readNumberArray()).toEqual([1, 2]);
    // Variation on spacing.
    stream = new StringStream('[ 1 2 ]');
    parser = new Type1Parser(stream, false, SEAC_ANALYSIS_ENABLED);
    expect(parser.readNumberArray()).toEqual([1, 2]);
  });

  it('skips comments', function() {
    var stream = new StringStream(
      '%!PS-AdobeFont-1.0: CMSY10 003.002\n' +
      '%%Title: CMSY10\n' +
      '%Version: 003.002\n' +
      'FontDirectory');
    var parser = new Type1Parser(stream, false, SEAC_ANALYSIS_ENABLED);
    expect(parser.getToken()).toEqual('FontDirectory');
  });

  it('parses font program', function() {
    var stream = new StringStream(
      '/ExpansionFactor  99\n' +
      '/Subrs 1 array\n' +
      'dup 0 1 RD x noaccess put\n' +
      'end\n' +
      '/CharStrings 46 dict dup begin\n' +
      '/.notdef 1 RD x ND\n' +
      'end');
    var parser = new Type1Parser(stream, false, SEAC_ANALYSIS_ENABLED);
    var program = parser.extractFontProgram();
    expect(program.charstrings.length).toEqual(1);
    expect(program.properties.privateData.ExpansionFactor).toEqual(99);
  });

  it('parses font header font matrix', function() {
    var stream = new StringStream(
      '/FontMatrix [0.001 0 0 0.001 0 0 ]readonly def\n');
    var parser = new Type1Parser(stream, false, SEAC_ANALYSIS_ENABLED);
    var props = {};
    parser.extractFontHeader(props);
    expect(props.fontMatrix).toEqual([0.001, 0, 0, 0.001, 0, 0]);
  });

  it('parses font header encoding', function() {
    var stream = new StringStream(
      '/Encoding 256 array\n' +
      '0 1 255 {1 index exch /.notdef put} for\n' +
      'dup 33 /arrowright put\n' +
      'readonly def\n');
    var parser = new Type1Parser(stream, false, SEAC_ANALYSIS_ENABLED);
    var props = { overridableEncoding: true };
    parser.extractFontHeader(props);
    expect(props.builtInEncoding[33]).toEqual('arrowright');
  });
});
