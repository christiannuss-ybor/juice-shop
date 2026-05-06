/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// Minimal in-memory document store with a Mongo-style query subset, written
// to replace the unmaintained `marsdb` (which carries an unfixed command-
// injection advisory). Only the field-equality queries actually used by the
// hardened routes are honoured — operator-based queries are deliberately not
// supported.

type Doc = Record<string, any>

class Collection<T extends Doc = Doc> {
  private readonly docs: T[] = []
  private nextId = 1

  async insert (doc: T): Promise<T> {
    const inserted: T = { _id: String(this.nextId++), ...doc }
    this.docs.push(inserted)
    return inserted
  }

  async find (query: Doc = {}): Promise<T[]> {
    return this.docs.filter(d => this.matches(d, query)).map(d => ({ ...d }))
  }

  async findOne (query: Doc): Promise<T> {
    const found = this.docs.find(d => this.matches(d, query))
    // The legacy MarsDB API used by callers always returns a falsy `T` when
    // there's no match; we keep that behaviour (callers null-check the
    // result before using it).
    return (found ? { ...found } : (null as unknown as T))
  }

  async update (query: Doc, mutation: Doc, options: { multi?: boolean } = {}): Promise<{ modified: number, original: T[] }> {
    const original: T[] = []
    let modified = 0
    for (const doc of this.docs) {
      if (!this.matches(doc, query)) continue
      original.push({ ...doc })
      this.applyMutation(doc, mutation)
      modified++
      if (!options.multi) break
    }
    return { modified, original }
  }

  async count (query: Doc = {}): Promise<number> {
    return this.docs.filter(d => this.matches(d, query)).length
  }

  private matches (doc: Doc, query: Doc): boolean {
    for (const [k, v] of Object.entries(query)) {
      // Reject operator/object queries — the hardened routes only use plain
      // equality. This intentionally fails closed for any unexpected query.
      if (v !== null && typeof v === 'object') return false
      if (doc[k] !== v) return false
    }
    return true
  }

  private applyMutation (doc: Doc, mutation: Doc) {
    if (mutation.$set) {
      for (const [k, v] of Object.entries(mutation.$set)) doc[k] = v
    }
    if (mutation.$inc) {
      for (const [k, v] of Object.entries(mutation.$inc as Record<string, number>)) {
        doc[k] = (typeof doc[k] === 'number' ? doc[k] : 0) + v
      }
    }
  }
}

export const reviewsCollection = new Collection<any>()
export const ordersCollection = new Collection<any>()
