/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { type Review } from '../data/types'
import * as db from '../data/mongodb'

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = typeof req.body.id === 'string' ? req.body.id : ''
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }
    if (!id) {
      return res.status(400).json({ error: 'Wrong Params' })
    }

    try {
      const review = await db.reviewsCollection.findOne({ _id: id })
      if (!review) {
        return res.status(404).json({ error: 'Not found' })
      }

      if ((review.likedBy ?? []).includes(user.data.email)) {
        return res.status(403).json({ error: 'Already liked' })
      }

      const updatedReview: Review = await db.reviewsCollection.findOne({ _id: id })
      const likedBy = Array.isArray(updatedReview.likedBy) ? updatedReview.likedBy.filter((e: string) => e !== user.data.email) : []
      likedBy.push(user.data.email)
      const result = await db.reviewsCollection.update(
        { _id: id },
        { $set: { likedBy }, $inc: { likesCount: 1 } }
      )
      res.json(result)
    } catch (err) {
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
