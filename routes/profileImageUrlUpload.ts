/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns from 'node:dns/promises'
import net from 'node:net'
import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const ALLOWED_IMAGE_EXT = ['jpg', 'jpeg', 'png', 'gif']
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:'])
const MAX_DOWNLOAD_BYTES = 1024 * 1024 // 1 MB

function isPrivateAddress (address: string): boolean {
  if (!net.isIP(address)) return true
  if (net.isIPv4(address)) {
    const parts = address.split('.').map(Number)
    if (parts[0] === 10) return true
    if (parts[0] === 127) return true
    if (parts[0] === 0) return true
    if (parts[0] === 169 && parts[1] === 254) return true
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
    if (parts[0] === 192 && parts[1] === 168) return true
    return false
  }
  // IPv6 — be conservative.
  const lower = address.toLowerCase()
  if (lower === '::1' || lower === '::') return true
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true
  if (lower.startsWith('fe80')) return true
  if (lower.startsWith('::ffff:')) return isPrivateAddress(lower.replace('::ffff:', ''))
  return false
}

async function urlIsSafe (raw: string): Promise<{ ok: true, parsed: URL } | { ok: false }> {
  let parsed: URL
  try { parsed = new URL(raw) } catch { return { ok: false } }
  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) return { ok: false }
  if (parsed.hostname === 'localhost') return { ok: false }
  try {
    const records = await dns.lookup(parsed.hostname, { all: true })
    for (const r of records) {
      if (isPrivateAddress(r.address)) return { ok: false }
    }
  } catch {
    return { ok: false }
  }
  return { ok: true, parsed }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = String(req.body.imageUrl)
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (!loggedInUser) {
        next(new Error('Authentication required'))
        return
      }

      const safety = await urlIsSafe(url)
      if (!safety.ok) {
        res.status(400).send('Image URL is not allowed.')
        return
      }
      const parsed = safety.parsed
      const extCandidate = parsed.pathname.split('.').slice(-1)[0]?.toLowerCase() ?? ''
      const ext = ALLOWED_IMAGE_EXT.includes(extCandidate) ? extCandidate : 'jpg'

      try {
        const response = await fetch(parsed.toString(), { redirect: 'error' })
        if (!response.ok || !response.body) {
          throw new Error('Image fetch failed')
        }
        const contentLength = Number(response.headers.get('content-length') ?? '0')
        if (contentLength > MAX_DOWNLOAD_BYTES) {
          throw new Error('Image too large')
        }
        const contentType = (response.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase()
        if (contentType && !contentType.startsWith('image/')) {
          throw new Error('Not an image')
        }
        const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
        await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
        const user = await UserModel.findByPk(loggedInUser.data.id)
        await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
      } catch (error) {
        logger.warn(`Failed to retrieve profile image: ${utils.getErrorMessage(error)}`)
        // No fallback to user-supplied URL — just leave the existing image untouched.
      }
    }
    res.location((process.env.BASE_PATH ?? '') + '/profile')
    res.redirect((process.env.BASE_PATH ?? '') + '/profile')
  }
}
