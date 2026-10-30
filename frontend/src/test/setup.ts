import '@testing-library/jest-dom/vitest'
import { afterEach } from 'vitest'
import { __resetGateDecisions } from '../data/gates'
import { __resetResourceCache } from '../data/resources'

// The resource cache and the decided-gate set are module-level; without this reset one test's
// data would leak into the next.
afterEach(() => {
  __resetResourceCache()
  __resetGateDecisions()
})
