/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// The "find-it / fix-it" coding-challenge feature was removed alongside the
// hardening of the codebase: there are no remaining intentional vulnerabilities
// to find. This stub keeps the import surface for any lingering callers but
// always returns an empty map.

interface CachedCodeChallenge {
  snippet: string
  vulnLines: number[]
  neutralLines: number[]
}

const EMPTY = new Map<string, CachedCodeChallenge>()

export const SNIPPET_PATHS = Object.freeze<string[]>([])

export async function getCodeChallenges (): Promise<Map<string, CachedCodeChallenge>> {
  return EMPTY
}
