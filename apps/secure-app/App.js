// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Secure — the named human's signing device.
//
// Flow: see the exact action awaiting your approval → Face ID → the device key
// signs the Authorization Context → the Class-A signoff is submitted to the
// gate. The signature this app produces verifies offline under
// @emilia-protocol/verify (proven in lib/ep-signoff.test.mjs).

import React, { useState, useCallback } from 'react';
import {
  SafeAreaView, View, Text, FlatList, Pressable, ActivityIndicator, StyleSheet, Alert,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { challengeFromContext, buildAttestation } from './lib/ep-signoff.mjs';
import { signChallenge, getEnrolledPublicKeyHex } from './lib/secure-key';
import { fetchPendingSignoffs, submitSignoff } from './lib/ep-client.mjs';

// Configure for your tenant. EXPO_PUBLIC_* vars are injected at build time.
const BASE_URL = process.env.EXPO_PUBLIC_EP_BASE_URL || 'https://www.emiliaprotocol.ai';
const RP_ID = process.env.EXPO_PUBLIC_EP_RP_ID || 'www.emiliaprotocol.ai';
const ORIGIN = `https://${RP_ID}`;
const TOKEN = process.env.EXPO_PUBLIC_EP_TOKEN || '';

// Demo signoff shown when no live token is configured, so the device flow is
// demonstrable in Expo Go without a backend.
const DEMO_PENDING = [{
  challenge_id: 'demo_signoff_1',
  summary: 'Release payment of $1,400,000 to Acme Corp',
  context: {
    '@version': 'EP-CONTEXT-v1',
    action: { type: 'fin/payment-release', amount: 1_400_000, currency: 'USD', payee: 'Acme Corp' },
    approver: 'you@example.com',
    nonce: 'demo-nonce-001',
    not_after: '2026-12-31T00:00:00Z',
  },
}];

export default function App() {
  const [pending, setPending] = useState(DEMO_PENDING);
  const [busy, setBusy] = useState(null);

  // Load pending signoffs on mount when a live token is configured. No token →
  // demo mode; state already initializes to DEMO_PENDING. setState happens in
  // the promise callbacks (external-system subscription), never synchronously.
  React.useEffect(() => {
    if (!TOKEN) return undefined;
    let cancelled = false;
    fetchPendingSignoffs({ baseUrl: BASE_URL, token: TOKEN })
      .then((data) => { if (!cancelled) setPending(data.signoffs || data || []); })
      .catch((e) => { if (!cancelled) Alert.alert('Could not load', e.message); });
    return () => { cancelled = true; };
  }, []);

  const approve = useCallback(async (item) => {
    setBusy(item.challenge_id);
    try {
      // 1. Compute the challenge bound to the EXACT action context.
      const challenge = await challengeFromContext(item.context);
      // 2. Face ID → the device key signs the challenge.
      const webauthn = await signChallenge(challenge, { rpId: RP_ID, origin: ORIGIN });
      // 3. Assemble the Class-A signoff.
      const approverId = await getEnrolledPublicKeyHex().catch(() => undefined);
      const attestation = buildAttestation({ context: item.context, webauthn, approverId });
      // 4. Submit (or, in demo mode, show the verifiable attestation).
      if (TOKEN) {
        await submitSignoff({ baseUrl: BASE_URL, challengeId: item.challenge_id, attestation, token: TOKEN });
        Alert.alert('Approved', 'Your signed approval was submitted.');
        setPending((p) => p.filter((x) => x.challenge_id !== item.challenge_id));
      } else {
        Alert.alert('Signed (demo)', 'A verifiable Class-A signoff was produced on-device.');
      }
    } catch (e) {
      Alert.alert('Not approved', String(e.message || e));
    } finally {
      setBusy(null);
    }
  }, []);

  return (
    <SafeAreaView style={styles.screen}>
      <StatusBar style="light" />
      <Text style={styles.title}>EMILIA Secure</Text>
      <Text style={styles.subtitle}>Approvals awaiting your signature</Text>
      <FlatList
        data={pending}
        keyExtractor={(i) => i.challenge_id}
        ListEmptyComponent={<Text style={styles.empty}>Nothing to approve.</Text>}
        renderItem={({ item }) => (
          <View style={styles.card}>
            <Text style={styles.summary}>{item.summary || item.context?.action?.type}</Text>
            <Text style={styles.meta}>{item.context?.action?.amount
              ? `$${Number(item.context.action.amount).toLocaleString()} ${item.context.action.currency || ''}` : ''}</Text>
            <Pressable
              style={[styles.btn, busy === item.challenge_id && styles.btnBusy]}
              disabled={busy === item.challenge_id}
              onPress={() => approve(item)}
            >
              {busy === item.challenge_id
                ? <ActivityIndicator color="#0b0b0c" />
                : <Text style={styles.btnText}>Approve with Face ID</Text>}
            </Pressable>
          </View>
        )}
      />
      <Text style={styles.footer}>Signatures verify offline · EP-SIGNOFF-v1 · key class A</Text>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: '#0b0b0c', paddingHorizontal: 20 },
  title: { color: '#f5c451', fontSize: 26, fontWeight: '700', marginTop: 12 },
  subtitle: { color: '#9aa0a6', fontSize: 14, marginBottom: 16 },
  empty: { color: '#6b7177', textAlign: 'center', marginTop: 40 },
  card: { backgroundColor: '#161719', borderRadius: 14, padding: 18, marginBottom: 14, borderWidth: 1, borderColor: '#26282b' },
  summary: { color: '#f4f5f6', fontSize: 17, fontWeight: '600' },
  meta: { color: '#8fd19e', fontSize: 15, marginTop: 4, marginBottom: 14 },
  btn: { backgroundColor: '#f5c451', borderRadius: 10, paddingVertical: 13, alignItems: 'center' },
  btnBusy: { opacity: 0.7 },
  btnText: { color: '#0b0b0c', fontWeight: '700', fontSize: 15 },
  footer: { color: '#4b5057', fontSize: 11, textAlign: 'center', paddingVertical: 10 },
});
