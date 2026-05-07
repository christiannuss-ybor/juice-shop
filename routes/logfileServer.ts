/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  // Server-side log files are sensitive: they leak request paths, IPs and
  // internal errors. Listing or serving them via a user-reachable HTTP route
  // is now disallowed in all cases.
  return (_req: Request, res: Response, next: NextFunction) => {
    res.status(403)
    next(new Error('Access to log files is disabled.'))
  }
}
