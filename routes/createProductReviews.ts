/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import { reviewsCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'

export function createProductReviews () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }
    const productId = Number(req.params.id)
    const message = typeof req.body.message === 'string' ? req.body.message.slice(0, 500) : ''
    if (!Number.isFinite(productId) || productId <= 0 || !message) {
      return res.status(400).json({ error: 'Wrong Params' })
    }

    try {
      // Author is always taken from the authenticated session — never from
      // the request body — so reviews cannot be forged.
      await reviewsCollection.insert({
        product: productId,
        message,
        author: user.data.email,
        likesCount: 0,
        likedBy: []
      })
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      return res.status(500).json({ error: 'Failed to create review' })
    }
  }
}
