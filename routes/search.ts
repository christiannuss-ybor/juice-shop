/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'

import * as utils from '../lib/utils'
import { ProductModel } from '../models/product'

export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (typeof criteria === 'string' ? criteria : String(criteria))
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    // Strip SQL/LIKE wildcards and quotes; the ORM still parameterizes the
    // value, so this keeps the matched surface predictable for users.
    const safeCriteria = criteria.replace(/[%_\\'"\s]/g, '')
    const pattern = `%${safeCriteria}%`

    ProductModel.findAll({
      where: {
        [Op.or]: [
          { name: { [Op.like]: pattern } },
          { description: { [Op.like]: pattern } }
        ]
      },
      order: [['name', 'ASC']]
    }).then((products) => {
      for (let i = 0; i < products.length; i++) {
        products[i].name = req.__(products[i].name)
        products[i].description = req.__(products[i].description)
      }
      res.json(utils.queryResultToJson(products))
    }).catch((error: Error) => {
      next(error)
    })
  }
}
