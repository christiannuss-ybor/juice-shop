/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// The "fix-it" coding-challenge UI is retired in this hardened build.
import { type NextFunction, type Request, type Response } from 'express'

export const readFixes = (_key: string) => ({ fixes: [] as string[], correct: -1 })

export const serveCodeFixes = () => (_req: Request, res: Response, _next: NextFunction) => {
  res.status(404).json({ error: 'Coding challenges are disabled.' })
}

export const checkCorrectFix = () => (_req: Request, res: Response, _next: NextFunction) => {
  res.status(404).json({ error: 'Coding challenges are disabled.' })
}
