/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// The "find-it" coding-challenge UI is retired in this hardened build.
// Endpoints respond with a stable "no challenges" payload so the frontend
// renders gracefully instead of crashing.

import { type NextFunction, type Request, type Response } from 'express'

interface CodeSnippet {
  snippet: string
  vulnLines: number[]
  neutralLines: number[]
}

export const retrieveCodeSnippet = async (_challengeKey: string): Promise<CodeSnippet | null> => null

export const retrieveChallengesWithCodeSnippet = async (): Promise<string[]> => []

export const serveCodeSnippet = () => (req: Request, res: Response, _next: NextFunction) => {
  res.status(404).json({ status: 'error', error: 'Coding challenges are disabled.' })
}

export const checkVulnLines = () => (req: Request, res: Response, _next: NextFunction) => {
  res.status(404).json({ status: 'error', error: 'Coding challenges are disabled.' })
}

export const getVerdict = (_vulnLines: number[], _neutralLines: number[], _selectedLines: number[]) => false
