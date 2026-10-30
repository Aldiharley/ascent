import '@testing-library/jest-dom/vitest'
import { afterEach } from 'vitest'
import { __resetResourceCache } from '../data/resources'

// The resource cache is module-level; without this reset one test's data would leak into the next.
afterEach(() => {
  __resetResourceCache()
})
