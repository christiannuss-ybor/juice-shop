/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import { type Request, type Response, type NextFunction } from 'express'

import logger from '../lib/logger'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

// Inline magic-byte sniffer for the only image types we accept. Avoids
// pulling in `file-type` which has had advisory CVEs around malformed input
// parsing in its broader codec support.
function detectImageType (buf: Buffer): { ext: string, mime: string } | null {
  if (buf.length < 12) return null
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return { ext: 'jpg', mime: 'image/jpeg' }
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return { ext: 'png', mime: 'image/png' }
  if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38) return { ext: 'gif', mime: 'image/gif' }
  if (
    buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46 &&
    buf[8] === 0x57 && buf[9] === 0x45 && buf[10] === 0x42 && buf[11] === 0x50
  ) return { ext: 'webp', mime: 'image/webp' }
  return null
}

export function profileImageFileUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const file = req.file
    const buffer = file?.buffer
    if (!buffer) {
      res.status(400)
      next(new Error('No file uploaded'))
      return
    }

    const detected = detectImageType(buffer)
    if (!detected || !detected.mime.startsWith('image/')) {
      res.status(415)
      next(new Error('Profile image upload does not accept this file type.'))
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Authentication required'))
      return
    }

    const filePath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${detected.ext}`
    try {
      await fs.writeFile(filePath, buffer)
    } catch (err) {
      logger.warn('Error writing file: ' + (err instanceof Error ? err.message : String(err)))
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (user != null) {
        await user.update({ profileImage: `assets/public/images/uploads/${loggedInUser.data.id}.${detected.ext}` })
      }
    } catch (error) {
      next(error)
      return
    }
    res.location((process.env.BASE_PATH ?? '') + '/profile')
    res.redirect((process.env.BASE_PATH ?? '') + '/profile')
  }
}
