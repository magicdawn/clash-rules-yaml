// https://github.com/Loyalsoldier/clash-rules

import YAML from 'js-yaml'
import fse from 'fs-extra'
import { fileURLToPath } from 'url'
import path from 'path'
import pmap from 'promise.map'
import { readUrl } from 'dl-vampire'

const read = (file: string) => fse.readFileSync(file, 'utf8')

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

type RuleProvider = {
  type: 'http'
  behavior: 'domain' | 'ipcidr' | 'classical'
  url: string
  payload: string[]
}

const ruleProviders = (
  YAML.load(read(__dirname + '/data/rule-providers.yml')) as {
    'rule-providers': Record<string, RuleProvider>
  }
)['rule-providers']
const rules = (YAML.load(read(__dirname + '/data/rules.yml')) as { rules: string[] }).rules

const providerNames = Object.keys(ruleProviders)
await pmap(
  providerNames,
  async (name) => {
    const provider = ruleProviders[name]
    const content = await readUrl({ url: provider.url, encoding: 'utf8' })
    provider.payload = (YAML.load(content) as any).payload as string[]
  },
  5
)

const transformedRules: string[] = rules
  .map((ruleLine) => {
    const [ruleType, ruleSetName, ruleSetTarget] = ruleLine.split(',')

    if (ruleType !== 'RULE-SET') return ruleLine

    const provider = ruleProviders[ruleSetName]
    if (!provider) return ''

    let lines: string[] = []
    const { behavior, payload } = provider

    if (behavior === 'classical') {
      lines = payload.map((s) => `${s},${ruleSetTarget}`)
    } else if (behavior === 'domain') {
      lines = payload.map((s) => `DOMAIN,${s},${ruleSetTarget}`)
    } else {
      lines = payload.map((s) => {
        if (s.includes(':')) {
          return `IP-CIDR6,${s},${ruleSetTarget}`
        } else {
          return `IP-CIDR,${s},${ruleSetTarget}`
        }
      })
    }

    return lines
  })
  .flat()
  .filter(Boolean)

const yamlStr = YAML.dump({ rules: transformedRules })
fse.outputFileSync(__dirname + '/../generated/rules.yml', yamlStr)
