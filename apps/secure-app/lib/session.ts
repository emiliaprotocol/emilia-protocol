// SPDX-License-Identifier: Apache-2.0
import * as SecureStore from 'expo-secure-store';
import { createPairedSessionVault } from './security-boundary.mjs';

export interface PairedSession {
  accessToken: string;
  expiresAt: string;
  approverId: string;
  profileId: string;
  platform: 'ios' | 'android';
  appId: string;
}

const vault = createPairedSessionVault({
  secureStore: SecureStore,
  storageOptions: {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  },
});

export async function savePairedSession(session: PairedSession): Promise<PairedSession> {
  return vault.save(session) as Promise<PairedSession>;
}

export async function loadPairedSession(): Promise<PairedSession | null> {
  return vault.load() as Promise<PairedSession | null>;
}

export async function clearPairedSession(): Promise<void> {
  await vault.clear();
}
