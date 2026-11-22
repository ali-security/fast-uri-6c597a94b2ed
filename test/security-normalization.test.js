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
