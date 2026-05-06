/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// The chatbot used to be backed by `juicy-chat-bot`, which depends on the
// deprecated `vm2` sandbox (CVE-laden, no patched release). Rather than ship
// a runtime sandbox-escape vector, we expose a static, non-evaluating chatbot
// shim. Existing client code on /rest/chatbot/* keeps working.

import { type Request, type Response } from 'express'
import config from 'config'

// `bot` and `initializeChatbot` remain exported so any consumers (most
// notably the existing API test suite) keep importing successfully — the bot
// is permanently null in this hardened build.
export const bot: any = null

export async function initializeChatbot () {
  // No-op — kept for compatibility with the existing startup wiring.
}

void initializeChatbot()

const greeting = (name: string) => {
  const botName = config.get<string>('application.chatBot.name')
  const tmpl = config.get<string>('application.chatBot.greeting')
  return tmpl.replace('<bot-name>', botName).replace('<customer-name>', name || 'guest')
}

export const status = () => (req: Request, res: Response) => {
  res.status(200).json({
    status: true,
    body: greeting('there')
  })
}

export const process = () => (req: Request, res: Response) => {
  res.status(200).json({
    action: 'response',
    body: config.get<string>('application.chatBot.defaultResponse')
  })
}
