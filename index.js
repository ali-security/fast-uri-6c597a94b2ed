'use strict'

const { normalizeIPv6, normalizeIPv4, removeDotSegments, removeDotSegmentsRelative, escapeFirstSegmentColon, recomposeAuthority, normalizePercentEncoding, normalizePathEncoding, escapePreservingEscapes, reescapeHostDelimiters } = require('./lib/utils')
const SCHEMES = require('./lib/schemes')

const MALFORMED_HOST_ERROR = 'URI host is malformed.'
// ASCII characters outside the RFC 3986 reg-name set (unreserved, sub-delims
// and "%" for pct-encoded): C0 controls, space, DEL, and "#/:<>?@[\]^`{|}.
const FORBIDDEN_DOMAIN_HOST_CHARACTER = /[\0-\x20"#/:<>?@[\\\]^`{|}\x7F]/u
const NON_ASCII_CHARACTER = /[^\0-\x7F]/u

// RFC 3986 section 3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
const VALID_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*$/u
const MALFORMED_SCHEME_ERROR = 'URI scheme is malformed.'

/**
 * Decodes a scheme and asserts the result is still a syntactically valid
 * scheme. Percent-decoding a scheme may otherwise reintroduce delimiters
 * ("//", ":", CR/LF) and turn the URI into a different one.
 *
 * @param {string} scheme
 * @returns {string}
 */
function decodeValidScheme (scheme) {
  const decodedScheme = unescape(String(scheme))
  if (!VALID_SCHEME.test(decodedScheme)) {
    throw new TypeError(MALFORMED_SCHEME_ERROR)
  }
  return decodedScheme
}

function normalize (uri, options) {
  if (typeof uri === 'string') {
    uri = normalizeString(uri, options)
  } else if (typeof uri === 'object') {
    uri = parse(serialize(uri, options), options)
  }
  return uri
}

function resolve (baseURI, relativeURI, options) {
  const schemelessOptions = Object.assign({ scheme: 'null' }, options)
  const {
    parsed: baseParsed,
    malformedAuthorityOrPort: baseMalformed,
    malformedScheme: baseMalformedScheme
  } = parseWithStatus(baseURI, schemelessOptions)
  const {
    parsed: relativeParsed,
    malformedAuthorityOrPort: relativeMalformed,
    malformedScheme: relativeMalformedScheme
  } = parseWithStatus(relativeURI, schemelessOptions)
  if (
    baseMalformed ||
    relativeMalformed ||
    baseMalformedScheme ||
    relativeMalformedScheme
  ) {
    throw new Error(baseParsed.error || relativeParsed.error || 'URI is malformed.')
  }
  const resolved = resolveComponents(baseParsed, relativeParsed, schemelessOptions, true)
  const resolvedSchemeHandler = SCHEMES[((options && options.scheme) || resolved.scheme || '').toLowerCase()]
  const resolvedHost = resolved.host
  const resolvedHostIsIP = resolvedHost !== undefined && resolvedHost !== '' &&
    (normalizeIPv4(resolvedHost).isIPV4 || normalizeIPv6(resolvedHost).isIPV6)
  // Inputs are parsed scheme-neutrally, so delimiters and controls in a domain
  // host are only detected here, once the final scheme is known. They always
  // fail closed, including in percent-encoded hosts.
  if (hasForbiddenDomainHost(resolved, options || {}, resolvedSchemeHandler, resolvedHostIsIP)) {
    throw new Error(MALFORMED_HOST_ERROR)
  }
  canonicalizeHost(resolved, options || {}, resolvedSchemeHandler, resolvedHostIsIP)
  // Percent escapes in an ASCII reg-name are encoded data. The WHATWG hostname
  // parser can reject them even though fast-uri preserves them safely as RFC
  // 3986 data. A raw non-ASCII host must still fail closed if conversion fails.
  const encodedASCIIHost = resolvedHost && resolvedHost.indexOf('%') !== -1 &&
    !NON_ASCII_CHARACTER.test(resolvedHost)
  if (resolved.error && !encodedASCIIHost) {
    throw new Error(resolved.error)
  }
  return serialize(resolved, { ...schemelessOptions, skipEscape: true })
}

function resolveComponents (base, relative, options, skipNormalization) {
  const target = {}
  if (!skipNormalization) {
    base = parse(serialize(base, options), options) // normalize base components
    relative = parse(serialize(relative, options), options) // normalize relative components
  }
  options = options || {}

  if (!options.tolerant && relative.scheme) {
    target.scheme = relative.scheme
    // target.authority = relative.authority;
    target.userinfo = relative.userinfo
    target.host = relative.host
    target.port = relative.port
    target.path = removeDotSegments(relative.path || '')
    target.query = relative.query
  } else {
    if (relative.userinfo !== undefined || relative.host !== undefined || relative.port !== undefined) {
      // target.authority = relative.authority;
      target.userinfo = relative.userinfo
      target.host = relative.host
      target.port = relative.port
      target.path = removeDotSegments(relative.path || '')
      target.query = relative.query
    } else {
      if (!relative.path) {
        target.path = base.path
        if (relative.query !== undefined) {
          target.query = relative.query
        } else {
          target.query = base.query
        }
      } else {
        if (relative.path.charAt(0) === '/') {
          target.path = removeDotSegments(relative.path)
        } else {
          const baseHasAuthority = base.userinfo !== undefined || base.host !== undefined || base.port !== undefined
          if (baseHasAuthority && !base.path) {
            target.path = '/' + relative.path
          } else if (!base.path) {
            target.path = relative.path
          } else {
            target.path = base.path.slice(0, base.path.lastIndexOf('/') + 1) + relative.path
          }
          target.path = !base.scheme && !baseHasAuthority && target.path.charAt(0) !== '/'
            ? removeDotSegmentsRelative(target.path)
            : removeDotSegments(target.path)
        }
        target.query = relative.query
      }
      // target.authority = base.authority;
      target.userinfo = base.userinfo
      target.host = base.host
      target.port = base.port
    }
    target.scheme = base.scheme
  }

  target.fragment = relative.fragment

  return target
}

function equal (uriA, uriB, options) {
  const normalizedA = normalizeComparableURI(uriA, options)
  const normalizedB = normalizeComparableURI(uriB, options)

  return normalizedA !== undefined && normalizedB !== undefined && normalizedA.toLowerCase() === normalizedB.toLowerCase()
}

function serialize (cmpts, opts) {
  const components = {
    host: cmpts.host,
    scheme: cmpts.scheme,
    userinfo: cmpts.userinfo,
    port: cmpts.port,
    path: cmpts.path,
    query: cmpts.query,
    nid: cmpts.nid,
    nss: cmpts.nss,
    uuid: cmpts.uuid,
    fragment: cmpts.fragment,
    reference: cmpts.reference,
    resourceName: cmpts.resourceName,
    secure: cmpts.secure,
    error: ''
  }
  const options = Object.assign({}, opts)
  const uriTokens = []

  if (components.scheme) {
    components.scheme = decodeValidScheme(components.scheme)
  }

  // find scheme handler
  const schemeHandler = SCHEMES[(options.scheme || components.scheme || '').toLowerCase()]

  // perform scheme specific serialization
  if (schemeHandler && schemeHandler.serialize) schemeHandler.serialize(components, options)

  const authority = recomposeAuthority(components)
  // A reference with no emitted scheme is path-noscheme: a bare ':' in its
  // first path segment would reparse as a scheme (RFC 3986 3.3/4.2). A suffix
  // reference never emits its scheme token, so it is path-noscheme as well.
  // Only an authority that is actually emitted protects the path. Enforced
  // under skipEscape too (resolve()), so the reapply below gates on this flag.
  const schemelessReference = (!components.scheme || options.reference === 'suffix') && authority === undefined
  const pathNoScheme = !options.skipEscape && schemelessReference

  if (components.path !== undefined) {
    if (!options.skipEscape) {
      components.path = escapePreservingEscapes(components.path)

      if (components.scheme !== undefined) {
        components.path = components.path.split('%3A').join(':')
      }
      if (pathNoScheme) {
        components.path = escapeFirstSegmentColon(components.path)
      }
    } else {
      components.path = normalizePercentEncoding(components.path)
    }
  }

  if (options.reference !== 'suffix' && components.scheme) {
    // Scheme handlers may replace the scheme during serialization.
    components.scheme = decodeValidScheme(components.scheme)
    uriTokens.push(components.scheme, ':')
  }

  if (authority !== undefined) {
    if (options.reference !== 'suffix') {
      uriTokens.push('//')
    }

    uriTokens.push(authority)

    if (components.path && components.path.charAt(0) !== '/') {
      uriTokens.push('/')
    }
  }
  if (components.path !== undefined) {
    let s = components.path

    if (!options.absolutePath && (!schemeHandler || !schemeHandler.absolutePath)) {
      // A relative-path reference keeps its unresolvable leading ".." segments
      // and must never become root-relative (RFC 3986 section 5.2.4 applies to
      // merged target paths, not to the reference itself). A reference with no
      // emitted scheme and no authority is such a relative-path reference.
      s = schemelessReference && s.charAt(0) !== '/'
        ? removeDotSegmentsRelative(s)
        : removeDotSegments(s)
    }

    // Dot-segment removal can expose a colon that was not originally in the
    // first segment, and skipEscape or absolutePath can leave one raw. Reapply
    // path-noscheme encoding so the serialized relative reference cannot be
    // reparsed as a URI scheme.
    if (schemelessReference) {
      s = escapeFirstSegmentColon(s)
    }

    if (authority === undefined) {
      s = s.replace(/^\/\//u, '/%2F') // don't allow the path to start with "//"
    }

    uriTokens.push(s)
  }

  if (components.query !== undefined) {
    uriTokens.push('?', components.query)
  }

  if (components.fragment !== undefined) {
    uriTokens.push('#', components.fragment)
  }
  return uriTokens.join('')
}

const hexLookUp = Array.from({ length: 127 }, (_v, k) => /[^!"$&'()*+,\-.;=_`a-z{}~]/u.test(String.fromCharCode(k)))

function nonSimpleDomain (value) {
  let code = 0
  for (let i = 0, len = value.length; i < len; ++i) {
    code = value.charCodeAt(i)
    if (code > 126 || hexLookUp[code]) {
      return true
    }
  }
  return false
}

/**
 * @param {string} host
 * @returns {boolean} whether the host is a bracketed IP literal
 */
function isIPLiteral (host) {
  return host[0] === '[' && host[host.length - 1] === ']'
}

/**
 * Convert a Unicode/IDN domain host to the ASCII form the WHATWG URL parser
 * (and therefore `fetch()`) would use, when the effective scheme uses domain
 * hosts.
 *
 * @param {import('./types/index').URIComponent} parsed
 * @param {import('./types/index').Options} options
 * @param {{ domainHost?: boolean, unicodeSupport?: boolean }|undefined} schemeHandler
 * @param {boolean} isIP
 * @returns {boolean} whether host conversion failed
 */
function canonicalizeHost (parsed, options, schemeHandler, isIP) {
  if (hasForbiddenDomainHost(parsed, options, schemeHandler, isIP)) {
    parsed.error = parsed.error || MALFORMED_HOST_ERROR
    return true
  }

  if (
    !options.unicodeSupport &&
    (!schemeHandler || !schemeHandler.unicodeSupport) &&
    parsed.host &&
    !isIPLiteral(parsed.host) &&
    (options.domainHost || (schemeHandler && schemeHandler.domainHost)) &&
    isIP === false &&
    nonSimpleDomain(parsed.host)
  ) {
    let url
    try {
      url = new URL('http://' + parsed.host)
    } catch (e) {
      parsed.error = parsed.error || "Host's domain name can not be converted to ASCII: " + e
      return true
    }
    // The WHATWG parser must have read the whole input as a host. Anything
    // else means it found a delimiter fast-uri did not, so its hostname would
    // describe a different authority.
    if (!isHostOnlyURL(url)) {
      parsed.error = parsed.error || MALFORMED_HOST_ERROR
      return true
    }
    parsed.host = url.hostname
  }
  return false
}

/**
 * Whether a domain host contains an ASCII character that RFC 3986 does not
 * allow in a reg-name (unreserved, sub-delims, or pct-encoded). Such a host is
 * rejected instead of being handed to the WHATWG URL parser, which would treat
 * "@" as a userinfo delimiter (silently dropping the data before it) and strip
 * TAB, LF, and CR. Non-ASCII characters remain allowed for IDNs.
 *
 * @param {import('./types/index').URIComponent} parsed
 * @param {import('./types/index').Options} options
 * @param {{ domainHost?: boolean }|undefined} schemeHandler
 * @param {boolean} isIP
 * @returns {boolean}
 */
function hasForbiddenDomainHost (parsed, options, schemeHandler, isIP) {
  return Boolean(
    parsed.host &&
    isIP === false &&
    !isIPLiteral(parsed.host) &&
    (options.domainHost || (schemeHandler && schemeHandler.domainHost)) &&
    FORBIDDEN_DOMAIN_HOST_CHARACTER.test(parsed.host)
  )
}

/**
 * @param {URL} url
 * @returns {boolean}
 */
function isHostOnlyURL (url) {
  return url.username === '' &&
    url.password === '' &&
    url.port === '' &&
    url.pathname === '/' &&
    url.search === '' &&
    url.hash === '' &&
    url.hostname !== ''
}

const URI_PARSE = /^(?:([^#/:?]+):)?(?:\/\/((?:([^#/?@]*)@)?(\[[^#/?\]]+\]|[^#/:?]*)(?::(\d*))?))?([^#?]*)(?:\?([^#]*))?(?:#((?:.|[\n\r])*))?/u

// Captures the authority component (between "//" and the next "/", "?" or "#"),
// with or without a scheme prefix, for the literal-backslash rejection below.
const AUTHORITY_PREFIX = /^(?:[^#/:?]+:)?\/\/([^/?#]*)/

// Captures the leading authority-introducer region after an optional scheme: a
// run of forward slashes, backslashes, and the characters the WHATWG URL parser
// removes before parsing (TAB U+0009, LF U+000A, CR U+000D). A valid introducer
// is exactly "//". Node treats "\" as "/" on special schemes and strips those
// characters first, so forms like "\\", "/\", "\/", "/<TAB>/", or a leading
// "<TAB>//" reach an authority in Node while fast-uri's URI_PARSE folds them into
// the path group (host confusion / SSRF / redirect bypass).
const AUTHORITY_INTRODUCER_REGION = /^(?:[^#/:?]+:)?([/\\\t\n\r]*)/

function getParseError (parsed, matches) {
  if (matches[2] !== undefined && parsed.path && parsed.path[0] !== '/') {
    return 'URI path must start with "/" when authority is present.'
  }

  if (typeof parsed.port === 'number' && (parsed.port < 0 || parsed.port > 65535)) {
    return 'URI port is malformed.'
  }

  return undefined
}

function hasSuffixAuthority (uri) {
  const authorityEnd = uri.search(/[/?#]/)
  const authority = authorityEnd === -1 ? uri : uri.slice(0, authorityEnd)
  const at = authority.lastIndexOf('@')
  const hostPort = authority.slice(at + 1)

  if (hostPort[0] === '[') return true

  const colon = hostPort.lastIndexOf(':')
  return colon === -1 || /^\d*$/u.test(hostPort.slice(colon + 1))
}

function parseWithStatus (uri, opts) {
  const options = Object.assign({}, opts)
  const parsed = {
    scheme: undefined,
    userinfo: undefined,
    host: '',
    port: undefined,
    path: '',
    query: undefined,
    fragment: undefined
  }
  const gotEncoding = uri.indexOf('%') !== -1
  let malformedAuthorityOrPort = false
  let malformedHost = false
  let malformedIPLiteral = false
  let malformedScheme = false
  let isIP = false
  if (options.reference === 'suffix') {
    if (options.scheme) {
      // Suffix references traditionally omit both the scheme and the "//"
      // authority marker. Preserve that interpretation for valid authorities,
      // but treat a non-numeric host-port suffix as a path. Otherwise inputs
      // such as "javascript:alert(1)" are emitted as live schemes.
      uri = options.scheme + (hasSuffixAuthority(uri) ? '://' : ':') + uri
    } else {
      uri = '//' + uri
    }
  }

  // A literal backslash (U+005C) is not a valid RFC 3986 URI character and is
  // not an authority delimiter. Reject it in the authority rather than
  // rewriting it: normalizing "\" -> "/" (WHATWG error recovery) could silently
  // change the resource identified by an otherwise-invalid input, and lets "\"
  // act as a host delimiter here while Node's native URL parses a different
  // host (SSRF / redirect / origin-allowlist bypass). Percent-encoded %5C is
  // untouched and remains valid encoded data.
  const authorityMatch = uri.match(AUTHORITY_PREFIX)
  if (authorityMatch !== null && authorityMatch[1].indexOf('\\') !== -1) {
    parsed.error = 'URI authority must not contain a literal backslash.'
    malformedAuthorityOrPort = true
  }

  // Reject a malformed or whitespace-smuggled authority introducer. fast-uri
  // only recognizes a literal "//"; anything else in the leading separator run
  // (a backslash, or a "//" that appears only after removing the TAB/LF/CR that
  // Node strips) means the authority fast-uri parses differs from the one Node's
  // URL resolves. Reject rather than rewrite, mirroring the literal-backslash
  // guard above. Percent-encoded forms (%5C, %09) are untouched, valid data.
  const introducerMatch = uri.match(AUTHORITY_INTRODUCER_REGION)
  if (introducerMatch !== null) {
    const region = introducerMatch[1]
    const normalizedRegion = region.replace(/[\t\n\r]/g, '')
    // Two or more leading separators introduce an authority.
    if (normalizedRegion.length >= 2) {
      if (normalizedRegion.slice(0, 2) !== '//') {
        parsed.error = parsed.error || 'URI authority must not contain a literal backslash.'
        malformedAuthorityOrPort = true
      } else if (region.length !== normalizedRegion.length) {
        parsed.error = parsed.error || 'URI authority introducer must not contain whitespace.'
        malformedAuthorityOrPort = true
      }
    }
  }

  const matches = uri.match(URI_PARSE)

  if (matches) {
    // store each component
    parsed.scheme = matches[1]
    parsed.userinfo = matches[3]
    parsed.host = matches[4]
    parsed.port = parseInt(matches[5], 10)
    parsed.path = matches[6] || ''
    parsed.query = matches[7]
    parsed.fragment = matches[8]

    // Decode the scheme before anything else consumes it: the decoded value is
    // what selects the scheme handler and what gets serialized back out, so a
    // scheme that only becomes a delimiter run ("//evil.example", a CR/LF pair,
    // an embedded ":") after decoding must be rejected instead of normalized
    // into a different URI.
    if (parsed.scheme !== undefined) {
      const decodedScheme = unescape(parsed.scheme)
      if (VALID_SCHEME.test(decodedScheme)) {
        // Deliberate deviation from upstream, which additionally lowercases here.
        // RFC 3986 case-normalization is not part of the fix: the scheme handler
        // lookup below lowercases on its own, and the grammar check above already
        // rejects every delimiter. Lowercasing would change parse().scheme and
        // normalize() output for schemes that 3.0.6 returned verbatim, so the
        // decoded scheme is kept as-is.
        parsed.scheme = decodedScheme
      } else {
        parsed.error = parsed.error || MALFORMED_SCHEME_ERROR
        malformedScheme = true
      }
    }

    // fix port number
    if (isNaN(parsed.port)) {
      parsed.port = matches[5]
    }

    const parseError = getParseError(parsed, matches)
    if (parseError !== undefined) {
      parsed.error = parsed.error || parseError
      malformedAuthorityOrPort = true
    }

    if (parsed.host) {
      const ipv4result = normalizeIPv4(parsed.host)
      if (ipv4result.isIPV4 === false) {
        const bracketedIPLiteral = isIPLiteral(parsed.host)
        const ipv6result = normalizeIPv6(parsed.host)
        isIP = ipv6result.isIPV6 || ipv6result.isIPVFuture === true
        malformedIPLiteral = bracketedIPLiteral && ipv6result.error === true
        parsed.host = isIP ? ipv6result.host : ipv6result.host.toLowerCase()

        if (malformedIPLiteral) {
          // A bracketed IP literal that does not parse must be rejected, not
          // rewritten: silently truncating or re-encoding it hands back a
          // different, valid-looking authority than the one that was supplied.
          parsed.error = parsed.error || MALFORMED_HOST_ERROR
          malformedAuthorityOrPort = true
        }
      } else {
        parsed.host = ipv4result.host
        isIP = true
      }
    }
    if (parsed.scheme === undefined && parsed.userinfo === undefined && parsed.host === undefined && parsed.port === undefined && parsed.query === undefined && !parsed.path) {
      parsed.reference = 'same-document'
    } else if (parsed.scheme === undefined) {
      parsed.reference = 'relative'
    } else if (parsed.fragment === undefined) {
      parsed.reference = 'absolute'
    } else {
      parsed.reference = 'uri'
    }

    // check for reference errors
    if (options.reference && options.reference !== 'suffix' && options.reference !== parsed.reference) {
      parsed.error = parsed.error || 'URI is not a ' + options.reference + ' reference.'
    }

    // find scheme handler
    const schemeHandler = SCHEMES[(options.scheme || parsed.scheme || '').toLowerCase()]

    // convert Unicode IDN -> ASCII IDN when the effective scheme uses domain hosts
    malformedHost = canonicalizeHost(parsed, options, schemeHandler, isIP)

    if (!schemeHandler || (schemeHandler && !schemeHandler.skipNormalize)) {
      // Resolution parses both inputs with the internal `null` scheme before
      // the effective scheme is known. Keep a reg-name host percent-encoded for
      // that step: decoding it here would turn encoded delimiters into raw ones
      // and hide raw delimiters behind re-escaping, so resolve() could not
      // reject them for domain-host schemes. The resolved authority is decoded
      // and re-escaped when it is serialized.
      // A validated IP literal is already normalized (its zone identifier keeps
      // its percent-encoded octets), and a malformed one is kept verbatim.
      if (gotEncoding && parsed.host !== undefined && !malformedIPLiteral && (isIP || options.scheme !== 'null')) {
        const host = isIP ? parsed.host : unescape(parsed.host)
        parsed.host = reescapeHostDelimiters(host, isIP)
      }
      if (parsed.path) {
        parsed.path = normalizePathEncoding(parsed.path)
      }
      if (parsed.fragment) {
        try {
          parsed.fragment = encodeURI(decodeURIComponent(parsed.fragment))
        } catch {
          parsed.error = parsed.error || 'URI malformed'
        }
      }
    }

    // perform scheme specific parsing
    if (schemeHandler && schemeHandler.parse) {
      schemeHandler.parse(parsed, options)
    }
  } else {
    parsed.error = parsed.error || 'URI can not be parsed.'
  }
  return { parsed, malformedAuthorityOrPort, malformedHost, malformedScheme }
}

function parse (uri, opts) {
  return parseWithStatus(uri, opts).parsed
}

function normalizeString (uri, opts) {
  const { parsed, malformedAuthorityOrPort, malformedHost, malformedScheme } = parseWithStatus(uri, opts)
  // a malformed authority, host, port or scheme must never be canonicalized
  // into a different, valid URI: hand the input back untouched
  return malformedAuthorityOrPort || malformedHost || malformedScheme ? uri : serialize(parsed, opts)
}

function normalizeComparableURI (uri, opts) {
  // serialization fails closed on a malformed scheme, and an unusable input
  // must compare unequal rather than propagate the error to the caller
  try {
    if (typeof uri === 'string') {
      const { parsed, malformedAuthorityOrPort, malformedHost, malformedScheme } = parseWithStatus(uri, opts)
      return malformedAuthorityOrPort || malformedHost || malformedScheme ? undefined : serialize(parsed, opts)
    }

    if (typeof uri === 'object') {
      return serialize(uri, opts)
    }
  } catch (e) {
    return undefined
  }
}

const fastUri = {
  SCHEMES,
  normalize,
  resolve,
  resolveComponents,
  equal,
  serialize,
  parse
}

module.exports = fastUri
module.exports.default = fastUri
module.exports.fastUri = fastUri
