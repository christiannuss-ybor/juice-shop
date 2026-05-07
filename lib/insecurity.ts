/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import jwt from 'jsonwebtoken'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */
// eslint-disable-next-line @typescript-eslint/prefer-ts-expect-error
// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

// Generate a fresh RSA keypair on every process start. Tokens become invalid on
// restart (acceptable trade-off) and the private key never touches disk.
const keyPair = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
})
const privateKey = keyPair.privateKey
export const publicKey = keyPair.publicKey

// HMAC secret comes from env in production deployments; otherwise a strong
// per-process random value. The DB is re-seeded on every startup, so HMAC'd
// security answers stay consistent within a process lifetime.
const hmacSecret = process.env.JUICE_SHOP_HMAC_SECRET ?? crypto.randomBytes(48).toString('hex')

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

// Non-secret short fingerprint used in order IDs etc. Switched off MD5 to SHA-256.
export const hash = (data: string) => crypto.createHash('sha256').update(String(data ?? '')).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', hmacSecret).update(String(data ?? '')).digest('hex')

const SCRYPT_KEYLEN = 64
const SCRYPT_PREFIX = 'scrypt$'

export const hashPassword = (plain: string): string => {
  const salt = crypto.randomBytes(16)
  const derived = crypto.scryptSync(String(plain ?? ''), salt, SCRYPT_KEYLEN)
  return `${SCRYPT_PREFIX}${salt.toString('hex')}$${derived.toString('hex')}`
}

export const verifyPassword = (plain: string, stored: string): boolean => {
  if (typeof stored !== 'string' || !stored) return false
  if (stored.startsWith(SCRYPT_PREFIX)) {
    const [, saltHex, hashHex] = stored.split('$')
    if (!saltHex || !hashHex) return false
    let salt: Buffer
    let expected: Buffer
    try {
      salt = Buffer.from(saltHex, 'hex')
      expected = Buffer.from(hashHex, 'hex')
    } catch {
      return false
    }
    if (expected.length !== SCRYPT_KEYLEN) return false
    const derived = crypto.scryptSync(String(plain ?? ''), salt, SCRYPT_KEYLEN)
    return crypto.timingSafeEqual(derived, expected)
  }
  return false
}

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

// Hand-rolled JWT auth middleware: the bundled `express-jwt@0.1.3` and
// `jsonwebtoken@0.4` are vulnerable to algorithm-confusion attacks and have
// CVEs filed against them. This wrapper enforces RS256 explicitly via our
// strict `verify()` helper.
export const isAuthorized = () => (req: Request, res: Response, next: NextFunction) => {
  const token = utils.jwtFrom(req)
  if (token && verify(token)) {
    const decoded = decode(token) as any
    if (decoded) {
      // express-jwt-compatible: stash the decoded payload on `req.user`.
      ;(req as any).user = decoded
      next()
      return
    }
  }
  res.status(401).json({ error: 'Unauthorized' })
}
export const denyAll = () => (_req: Request, res: Response, _next: NextFunction) => {
  res.status(401).json({ error: 'Unauthorized' })
}
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const verify = (token: string) => {
  if (!token || typeof token !== 'string') return false
  try {
    jwt.verify(token, publicKey, { algorithms: ['RS256'] })
    return true
  } catch {
    return false
  }
}
export const decode = (token: string) => {
  if (!token || typeof token !== 'string') return undefined
  try {
    const decoded = jwt.decode(token, { complete: false }) as any
    return decoded ?? undefined
  } catch {
    return undefined
  }
}

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => sanitizeHtmlLib(input, { allowedTags: [], allowedAttributes: {} })
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
export const sanitizeSecure = (html: string): string => {
  let prev = String(html ?? '')
  for (let i = 0; i < 4; i++) {
    const next = sanitizeHtml(prev)
    if (next === prev) return next
    prev = next
  }
  return prev
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }
  const decoded = z85.decode(coupon)
  if (decoded && (hasValidFormat(decoded.toString()) != null)) {
    const parts = decoded.toString().split('-')
    const validity = parts[0]
    if (utils.toMMMYY(new Date()) === validity) {
      const discount = parseInt(parts[1], 10)
      if (Number.isFinite(discount) && discount >= 0 && discount <= 50) {
        return discount
      }
    }
  }
  return undefined
}

function hasValidFormat (coupon: string) {
  return coupon.match(/^(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{1,2}$/)
}

// Strict allowlist: redirects must match an entry exactly (no substring tricks).
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  if (typeof url !== 'string') return false
  return redirectAllowlist.has(url)
}

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  const mac = crypto.createHmac('sha256', hmacSecret)
  return mac.update(String(email ?? '') + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isAdmin = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.admin) {
      next()
    } else {
      res.status(403).json({ error: 'Forbidden' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error: unknown) {
      res.status(401).json({ status: 'error', message: utils.getErrorMessage(error) })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token && verify(token)) {
    const decoded = decode(token) as any
    if (decoded && authenticatedUsers.get(token) === undefined) {
      authenticatedUsers.put(token, decoded)
      res.cookie('token', token, {
        httpOnly: true,
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production'
      })
    }
  }
  next()
}
