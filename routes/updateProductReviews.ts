/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

export function updateProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }
    const id = typeof req.body.id === 'string' ? req.body.id : ''
    const message = typeof req.body.message === 'string' ? req.body.message : ''
    if (!id || !message) {
      return res.status(400).json({ error: 'Wrong Params' })
    }
    try {
      const review = await db.reviewsCollection.findOne({ _id: id })
      if (!review) {
        return res.status(404).json({ error: 'Not found' })
      }
      if (review.author !== user.data.email) {
        return res.status(403).json({ error: 'Forbidden' })
      }
      const result = await db.reviewsCollection.update(
        { _id: id, author: user.data.email },
        { $set: { message } }
      )
      res.json(result)
    } catch (err) {
      res.status(500).json({ error: 'Failed to update review' })
    }
  }
}
