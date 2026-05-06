/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import config from 'config'
import * as utils from '../utils'

interface ReplaceOpts { regex: RegExp, replacement: string, paths: string[] }
const replace = ({ regex, replacement, paths }: ReplaceOpts) => {
  for (const p of paths) {
    try {
      const content = fs.readFileSync(p, 'utf8')
      const next = content.replace(regex, replacement)
      if (next !== content) fs.writeFileSync(p, next)
    } catch { /* ignore — file may not exist */ }
  }
}

const customizeEasterEgg = async () => {
  if (config.has('application.easterEggPlanet.overlayMap')) {
    let overlay: string = config.get('application.easterEggPlanet.overlayMap')
    if (utils.isUrl(overlay)) {
      const overlayPath = overlay
      overlay = utils.extractFilename(overlay)
      await utils.downloadToFile(overlayPath, 'frontend/dist/frontend/assets/private/' + overlay)
    }
    replaceImagePath(overlay)
  }
  if (config.has('application.easterEggPlanet.name')) {
    replaceThreeJsTitleTag()
  }
}

const replaceImagePath = (overlay: string) => {
  const textureDeclaration = 'orangeTexture = THREE.ImageUtils.loadTexture("/assets/private/' + overlay + '");'
  replace({
    regex: /orangeTexture = .*;/,
    replacement: textureDeclaration,
    paths: ['frontend/dist/frontend/assets/private/threejs-demo.html']
  })
}

const replaceThreeJsTitleTag = () => {
  const threeJsTitleTag = '<title>Welcome to Planet ' + config.get<string>('application.easterEggPlanet.name') + '</title>'
  replace({
    regex: /<title>.*<\/title>/,
    replacement: threeJsTitleTag,
    paths: ['frontend/dist/frontend/assets/private/threejs-demo.html']
  })
}

export default customizeEasterEgg
