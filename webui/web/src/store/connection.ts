import { create } from 'zustand'
import type { Status } from '@/api/client'

interface ConnectionStore {
  status: Status | null
  setStatus: (s: Status) => void
}

export const useConnectionStore = create<ConnectionStore>((set) => ({
  status: null,
  setStatus: (status) => set({ status }),
}))
