/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as utils from '../lib/utils'

const ALLOWED_UPLOAD_EXT = new Set(['pdf', 'zip'])
const MAX_UPLOAD_SIZE = 200_000
const COMPLAINTS_DIR = path.resolve('uploads/complaints')

try { fs.mkdirSync(COMPLAINTS_DIR, { recursive: true }) } catch { /* ignore */ }

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  if (file && file.size > MAX_UPLOAD_SIZE) {
    return res.status(413).json({ error: 'File is too large' })
  }
  next()
}

function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  if (!fileType || !ALLOWED_UPLOAD_EXT.has(fileType)) {
    return res.status(415).json({ error: 'File type not allowed' })
  }
  next()
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (!utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    next()
    return
  }
  if (!file?.buffer) {
    res.status(400).json({ error: 'No zip payload' })
    return
  }
  // Sanitise the filename and stream entries to a contained directory,
  // refusing any path that would escape the complaints upload root.
  const safeName = path.basename(file.originalname).toLowerCase().replace(/[^a-z0-9._-]/g, '_')
  const tempFile = path.join(os.tmpdir(), safeName)
  fs.writeFile(tempFile, file.buffer, function (writeErr) {
    if (writeErr) { next(writeErr); return }
    fs.createReadStream(tempFile)
      .pipe(unzipper.Parse())
      .on('entry', function (entry: any) {
        const rawEntry = String(entry.path ?? '')
        const entryName = path.basename(rawEntry)
        if (!entryName || entryName === '.' || entryName === '..') {
          entry.autodrain(); return
        }
        const target = path.resolve(COMPLAINTS_DIR, entryName)
        if (target !== COMPLAINTS_DIR && !target.startsWith(COMPLAINTS_DIR + path.sep)) {
          entry.autodrain(); return
        }
        if (entry.type !== 'File') { entry.autodrain(); return }
        entry.pipe(fs.createWriteStream(target).on('error', (err) => { next(err) }))
      })
      .on('error', (err: unknown) => { next(err) })
      .on('close', () => { fs.unlink(tempFile, () => {}) })
  })
  res.status(204).end()
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    res.status(410)
    next(new Error('B2B customer complaints via XML file upload have been disabled for security reasons.'))
    return
  }
  next()
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
    res.status(410)
    next(new Error('B2B customer complaints via YAML file upload have been disabled for security reasons.'))
    return
  }
  res.status(204).end()
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
}
