/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'

import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import { type User } from '../data/types'
import * as utils from '../lib/utils'

export function login () {
  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {
    BasketModel.findOrCreate({ where: { UserId: user.data.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        const token = security.authorize(user)
        user.bid = basket.id
        security.authenticatedUsers.put(token, user)
        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })
      }).catch((error: Error) => {
        next(error)
      })
  }

  return (req: Request, res: Response, next: NextFunction) => {
    const email = typeof req.body?.email === 'string' ? req.body.email : ''
    const password = typeof req.body?.password === 'string' ? req.body.password : ''

    if (!email || !password) {
      res.status(401).send(res.__('Invalid email or password.'))
      return
    }

    UserModel.findOne({ where: { email, deletedAt: null } as any })
      .then((authenticatedUser: UserModel | null) => {
        if (!authenticatedUser || !security.verifyPassword(password, authenticatedUser.password)) {
          // Generic message; do not leak which side was wrong.
          res.status(401).send(res.__('Invalid email or password.'))
          return
        }
        const user = utils.queryResultToJson(authenticatedUser)
        if (user.data?.id && user.data.totpSecret !== '') {
          res.status(401).json({
            status: 'totp_token_required',
            data: {
              tmpToken: security.authorize({
                userId: user.data.id,
                type: 'password_valid_needs_second_factor_token'
              })
            }
          })
        } else if (user.data?.id) {
          // @ts-expect-error FIXME some properties missing in user
          afterLogin(user, res, next)
        } else {
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
}
