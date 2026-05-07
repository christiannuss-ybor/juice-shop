/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    // The previous implementation evaluated `orderLinesData` as JS in a
    // sandboxed VM (RCE-prone). It is now treated as opaque structured data:
    // accept JSON only, with hard size limits and no execution.
    const orderLinesData = body?.orderLinesData
    if (orderLinesData !== undefined) {
      const serialised = typeof orderLinesData === 'string' ? orderLinesData : JSON.stringify(orderLinesData)
      if (serialised.length > 4096) {
        res.status(413)
        next(new Error('orderLinesData is too large'))
        return
      }
      try {
        if (typeof orderLinesData === 'string') JSON.parse(orderLinesData)
      } catch {
        res.status(400)
        next(new Error('orderLinesData must be valid JSON'))
        return
      }
    }
    res.json({ cid: body?.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
