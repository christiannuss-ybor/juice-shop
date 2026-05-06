/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'

const FTP_ROOT = path.resolve('ftp')

const ALLOWED_FILES = new Set([
  'announcement_encrypted.md',
  'legal.md',
  'package.json',
  'incident-support.kdbx'
])

export function servePublicFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const requestedRaw = String(params.file ?? '')
    if (!requestedRaw) {
      res.status(403)
      next(new Error('Forbidden'))
      return
    }
    const requested = decodeURIComponent(requestedRaw)
    if (requested.includes('/') || requested.includes('\\') || requested.includes('\0') || requested.includes('%00')) {
      res.status(403)
      next(new Error('Invalid file name'))
      return
    }

    if (!ALLOWED_FILES.has(requested) && !endsWithAllowlistedFileType(requested)) {
      res.status(403)
      next(new Error('Only specifically published .md and .pdf files are allowed.'))
      return
    }

    const resolved = path.resolve(FTP_ROOT, requested)
    if (!resolved.startsWith(FTP_ROOT + path.sep) && resolved !== FTP_ROOT) {
      res.status(403)
      next(new Error('Path traversal blocked'))
      return
    }

    res.sendFile(resolved)
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
