'use strict'

const test = require('tape')
const fastURI = require('..')

test('parse preserves reserved path escapes as data', (t) => {
  const components = fastURI.parse('http://example.com/a%2Fb/public/%2e%2e/admin')

  t.equal(components.path, '/a%2Fb/public/%2E%2E/admin')
  t.end()
})

test('normalize preserves percent-encoded path separators and dot segments', (t) => {
  t.equal(
    fastURI.normalize('http://example.com/public/%2e%2e/admin'),
    'http://example.com/public/%2E%2E/admin'
  )

  t.equal(
    fastURI.normalize('http://example.com/a%2Fb'),
    'http://example.com/a%2Fb'
  )

  t.end()
})

test('resolve does not decode reserved path escapes into live path syntax', (t) => {
  t.equal(
    fastURI.resolve('http://example.com/public/', '%2e%2e/admin'),
    'http://example.com/public/%2E%2E/admin'
  )

  t.equal(
    fastURI.resolve('http://example.com/a/b', 'c%2Fd'),
    'http://example.com/a/c%2Fd'
  )

  t.end()
})

test('equal does not treat reserved path escapes as live path syntax', (t) => {
  t.equal(
    fastURI.equal('http://example.com/public/%2e%2e/admin', 'http://example.com/admin', {}),
    false
  )

  t.equal(
    fastURI.equal('http://example.com/a%2Fb', 'http://example.com/a/b', {}),
    false
  )

  t.end()
})

test('equal does not decode reserved path escapes in component objects', (t) => {
  t.equal(
    fastURI.equal({ scheme: 'http', host: 'example.com', path: '/public/%2e%2e/admin' }, 'http://example.com/admin', {}),
    false
  )

  t.equal(
    fastURI.equal({ scheme: 'http', host: 'example.com', path: '/a%2Fb' }, 'http://example.com/a/b', {}),
    false
  )

  t.end()
})

test('serialize with skipEscape keeps reserved path escapes encoded', (t) => {
  t.equal(
    fastURI.serialize({ scheme: 'http', host: 'example.com', path: '/public/%2e%2e/admin' }, { skipEscape: true }),
    'http://example.com/public/%2E%2E/admin'
  )

  t.end()
})

test('half-encoded dot segments are not removed as live dot segments', (t) => {
  t.equal(
    fastURI.normalize('http://example.com/public/.%2e/admin'),
    'http://example.com/public/.%2E/admin'
  )

  t.equal(
    fastURI.resolve('http://example.com/public/', '%2e./admin'),
    'http://example.com/public/%2E./admin'
  )

  t.equal(
    fastURI.equal('http://example.com/public/.%2e/admin', 'http://example.com/admin', {}),
    false
  )

  t.end()
})

test('resolve decodes path escapes at most once', (t) => {
  t.equal(
    fastURI.resolve('http://example.com/public/', '%252e%252e/admin'),
    'http://example.com/public/%252e%252e/admin'
  )

  t.end()
})

test('resolve does not double-decode a percent-encoded escape in the host', (t) => {
  t.equal(
    fastURI.resolve('foo://trusted.example/', '//%2541.example/'),
    'foo://%2541.example/'
  )

  t.end()
})

test('scheme-relative hostname normalization folds decoded ASCII case', (t) => {
  const encodedHost = '//%41.com'
  const normalizedHost = fastURI.normalize(encodedHost)
  const encodedMetadata = '//%4Detadata.internal/private'
  const literalMetadata = '//metadata.internal/private'

  t.equal(fastURI.parse(encodedHost).host, 'a.com', 'parse folds an encoded uppercase host letter')
  t.equal(normalizedHost, '//a.com', 'normalize emits a lowercase host')
  t.equal(fastURI.normalize(normalizedHost), normalizedHost, 'host normalization is idempotent')
  t.equal(fastURI.equal(encodedHost, '//a.com'), true, 'encoded and literal host spellings compare equal')
  t.equal(fastURI.equal(encodedMetadata, literalMetadata), true, 'encoded metadata host compares equal')
  t.equal(
    fastURI.resolve('x://trusted.example/', encodedMetadata),
    fastURI.resolve('x://trusted.example/', literalMetadata),
    'encoded and literal metadata hosts resolve identically'
  )
  t.equal(
    fastURI.normalize('//example.com%2fpath'),
    '//example.com%2Fpath',
    'reserved host escapes remain encoded with uppercase hex'
  )
  t.equal(fastURI.normalize('//%2541.com'), '//%2541.com', 'nested host escapes are not decoded twice')
  // `equal()` lowercases both sides before comparing, so case sensitivity of the
  // other components is asserted through `normalize()`, which preserves case.
  t.equal(fastURI.normalize('//User@%41.com/path'), '//User@a.com/path', 'userinfo remains case-sensitive')
  t.equal(fastURI.normalize('//%41.com/Path'), '//a.com/Path', 'path remains case-sensitive')
  t.equal(fastURI.normalize('//%41.com/?Token=Value'), '//a.com/?Token=Value', 'query remains case-sensitive')
  t.end()
})

test('host normalization applies to schemes that skip path normalization', (t) => {
  const encodedHost = 'mailto://%41.com'
  const literalHost = 'mailto://a.com'

  t.equal(fastURI.parse(encodedHost).host, fastURI.parse(literalHost).host, 'parse results have consistent hosts')
  t.equal(fastURI.normalize(encodedHost), fastURI.normalize(literalHost), 'normalize results are consistent')
  t.equal(fastURI.equal(encodedHost, literalHost), true, 'encoded and literal hosts compare equal')
  // `urn` is the registered skipNormalize handler in this version, so it probes
  // that host normalization now runs outside the skipNormalize guard.
  t.equal(fastURI.parse('urn://%41.com').host, 'a.com', 'skipNormalize schemes still fold the host')
  t.end()
})

test('decoded host case folding covers escape spellings and non-domain schemes', (t) => {
  t.equal(fastURI.parse('//%4detadata.internal/private').host, 'metadata.internal', 'lowercase-hex escapes fold the decoded letter')
  t.equal(fastURI.parse('x://%4Detadata.internal/private').host, 'metadata.internal', 'unregistered schemes fold the decoded host')
  t.equal(fastURI.parse('//%41%2f.com').host, 'a%2F.com', 'remaining reserved escapes keep uppercase hex after folding')
  t.equal(fastURI.parse('http://%4Detadata.internal/private').host, 'metadata.internal', 'domain-host schemes stay folded')
  t.equal(
    fastURI.resolve('x://trusted.example/', '//%4Detadata.internal/private'),
    'x://metadata.internal/private',
    'resolve emits the folded host'
  )
  t.equal(
    fastURI.resolve('x://%4Detadata.internal/public/', '../private'),
    'x://metadata.internal/private',
    'resolve emits the folded host inherited from the base'
  )
  t.end()
})
