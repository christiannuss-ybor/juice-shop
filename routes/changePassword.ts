/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as utils from '../lib/utils'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

export function changePassword () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const source = req.method === 'POST' ? (req.body ?? {}) : (req.query ?? {})
    const currentPassword = typeof source.current === 'string' ? source.current : ''
    const newPassword = typeof source.new === 'string' ? source.new : ''
    const repeatPassword = typeof source.repeat === 'string' ? source.repeat : ''

    if (!newPassword || newPassword === 'undefined') {
      res.status(400).send(res.__('Password cannot be empty.'))
      return
    }
    if (newPassword !== repeatPassword) {
      res.status(400).send(res.__('New and repeated password do not match.'))
      return
    }
    if (newPassword.length < 8) {
      res.status(400).send(res.__('Password must be at least 8 characters long.'))
      return
    }

    const token = utils.jwtFrom(req)
    const loggedInUser = token ? security.authenticatedUsers.get(token) : undefined
    if (!loggedInUser) {
      res.status(401).send(res.__('You are not logged in.'))
      return
    }

    if (!currentPassword || !security.verifyPassword(currentPassword, loggedInUser.data.password)) {
      res.status(401).send(res.__('Current password is not correct.'))
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        res.status(404).send(res.__('User not found.'))
        return
      }
      await user.update({ password: newPassword })
      res.json({ user: { id: user.id, email: user.email } })
    } catch (error) {
      next(error)
    }
  }
}
