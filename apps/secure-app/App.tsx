// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Secure Expo shell.
//
// This build can exchange an admin-created pairing code for a non-bundled,
// server-minted mobile session and display that approver's inbox. Its only
// signer is an exportable JavaScript key, so live approval submission is absent.

import React, { useCallback, useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  Platform,
  Pressable,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { challengeFromContext, buildAttestation } from './lib/ep-signoff';
import { signChallengeWithSoftwareKey, type SigningPolicy } from './lib/secure-key';
import {
  exchangeMobilePairing,
  fetchMobileInbox,
  revokeMobileSession,
} from './lib/ep-client';
import {
  clearPairedSession,
  loadPairedSession,
  savePairedSession,
  type PairedSession,
} from './lib/session';

const APP_ID = 'ai.emiliaprotocol.secure';
const RP_ID = 'www.emiliaprotocol.ai';
const ORIGIN = `https://${RP_ID}`;
const LOCAL_SOFTWARE_POLICY: SigningPolicy = Object.freeze({
  requiredKeyProvenance: 'software_allowed',
  userVerification: 'biometric_only',
});

interface MobileAction {
  action_reference?: string;
  lifecycle?: string;
  presentation?: {
    title?: string;
    summary?: string;
    risk?: string;
    consequence?: string;
    material_fields?: Record<string, string>;
  };
}

const LOCAL_CONTEXT = {
  '@version': 'EP-CONTEXT-v1',
  action: { type: 'local/software-key-diagnostic', consequence: 'none' },
  approver: 'local-diagnostic-only',
  nonce: 'not-for-submission',
  not_after: '2099-01-01T00:00:00Z',
};

export default function App(): React.JSX.Element {
  const [session, setSession] = useState<PairedSession | null>(null);
  const [actions, setActions] = useState<MobileAction[]>([]);
  const [pairingCode, setPairingCode] = useState('');
  const [busy, setBusy] = useState<string | null>('startup');

  const refreshInbox = useCallback(async (activeSession: PairedSession): Promise<void> => {
    setBusy('refresh');
    try {
      const inbox = await fetchMobileInbox({ session: activeSession });
      setActions(inbox.actions);
    } catch (error) {
      Alert.alert('Inbox unavailable', String((error as Error).message || error));
      setActions([]);
    } finally {
      setBusy(null);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    loadPairedSession()
      .then(async (stored) => {
        if (cancelled) return;
        setSession(stored);
        if (stored) await refreshInbox(stored);
      })
      .catch((error) => {
        if (!cancelled) Alert.alert('Session unavailable', String((error as Error).message || error));
      })
      .finally(() => { if (!cancelled) setBusy(null); });
    return () => { cancelled = true; };
  }, [refreshInbox]);

  const pair = useCallback(async (): Promise<void> => {
    if (Platform.OS !== 'ios' && Platform.OS !== 'android') {
      Alert.alert('Pairing refused', 'Pairing is supported only in an iOS or Android native build.');
      return;
    }
    setBusy('pair');
    try {
      const paired = await exchangeMobilePairing({
        pairingCode,
        platform: Platform.OS,
        appId: APP_ID,
      });
      await savePairedSession(paired);
      setSession(paired);
      setPairingCode('');
      await refreshInbox(paired);
      Alert.alert(
        'Session paired',
        'The server session is active. Trusted platform-key enrollment is still required for live approvals.'
      );
    } catch (error) {
      Alert.alert('Pairing refused', String((error as Error).message || error));
    } finally {
      setBusy(null);
    }
  }, [pairingCode, refreshInbox]);

  const disconnect = useCallback(async (): Promise<void> => {
    if (!session) return;
    setBusy('disconnect');
    try {
      await revokeMobileSession({ session });
      await clearPairedSession();
      setSession(null);
      setActions([]);
    } catch (error) {
      Alert.alert(
        'Disconnect not completed',
        `The server session may still be active, so the local credential was retained. ${String((error as Error).message || error)}`
      );
    } finally {
      setBusy(null);
    }
  }, [session]);

  const runLocalSoftwareCheck = useCallback(async (): Promise<void> => {
    setBusy('software');
    try {
      const challenge = await challengeFromContext(LOCAL_CONTEXT);
      const result = await signChallengeWithSoftwareKey(challenge, {
        rpId: RP_ID,
        origin: ORIGIN,
        policy: LOCAL_SOFTWARE_POLICY,
      });
      const evidence = buildAttestation({ context: LOCAL_CONTEXT, webauthn: result.webauthn });
      if ('key_class' in evidence) throw new Error('client evidence unexpectedly assigned a key class');
      Alert.alert(
        'Local software signature created',
        'Exportable software key; biometric-only local gate; no WebAuthn UP/UV claim; not Class A; not submitted.'
      );
    } catch (error) {
      Alert.alert('Local signature not created', String((error as Error).message || error));
    } finally {
      setBusy(null);
    }
  }, []);

  return (
    <SafeAreaView style={styles.screen}>
      <StatusBar style="light" />
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.title}>EMILIA Secure</Text>
        <Text style={styles.subtitle}>Paired inbox shell · software signer is local-only</Text>

        <View style={styles.warning}>
          <Text style={styles.warningTitle}>No hardware-backed signer in this Expo build</Text>
          <Text style={styles.copy}>
            The JavaScript P-256 key is exportable. Live Class-A approval is disabled until a native
            passkey plus App Attest or Play Integrity enrollment is verified by the server.
          </Text>
        </View>

        {busy === 'startup' ? <ActivityIndicator color="#f5c451" /> : null}

        {!session ? (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Pair a server session</Text>
            <Text style={styles.copy}>
              Enter a one-time code created by an authorized tenant administrator. The resulting
              bearer credential is stored at runtime in device-only SecureStore, never in the bundle.
            </Text>
            <TextInput
              autoCapitalize="characters"
              autoCorrect={false}
              placeholder="ABCD-EFGH-JKLM"
              placeholderTextColor="#60656c"
              style={styles.input}
              value={pairingCode}
              onChangeText={setPairingCode}
            />
            <Pressable style={styles.btn} disabled={busy !== null} onPress={pair}>
              <Text style={styles.btnText}>{busy === 'pair' ? 'Pairing…' : 'Pair session'}</Text>
            </Pressable>
          </View>
        ) : (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Paired as {session.approverId}</Text>
            <Text style={styles.meta}>Profile: {session.profileId}</Text>
            <Text style={styles.copy}>
              Pairing authenticates the inbox session; it is not device-key enrollment and grants no
              assurance class. Live decision controls remain disabled in this shell.
            </Text>
            <View style={styles.row}>
              <Pressable style={[styles.btn, styles.rowButton]} disabled={busy !== null} onPress={() => refreshInbox(session)}>
                <Text style={styles.btnText}>{busy === 'refresh' ? 'Refreshing…' : 'Refresh inbox'}</Text>
              </Pressable>
              <Pressable style={[styles.secondaryBtn, styles.rowButton]} disabled={busy !== null} onPress={disconnect}>
                <Text style={styles.secondaryText}>{busy === 'disconnect' ? 'Disconnecting…' : 'Disconnect'}</Text>
              </Pressable>
            </View>
          </View>
        )}

        {session ? (
          <View>
            <Text style={styles.sectionTitle}>Server-authorized inbox</Text>
            {actions.length === 0 ? <Text style={styles.empty}>Nothing awaiting review.</Text> : null}
            {actions.map((item, index) => (
              <View style={styles.card} key={item.action_reference || String(index)}>
                <Text style={styles.cardTitle}>{item.presentation?.title || item.action_reference || 'Action'}</Text>
                <Text style={styles.copy}>{item.presentation?.summary || 'No summary supplied.'}</Text>
                <Text style={styles.meta}>Risk: {item.presentation?.risk || 'unspecified'}</Text>
                <Text style={styles.meta}>Consequence: {item.presentation?.consequence || 'unspecified'}</Text>
                {Object.entries(item.presentation?.material_fields || {}).map(([key, value]) => (
                  <Text style={styles.field} key={key}>{key}: {value}</Text>
                ))}
                <Text style={styles.disabled}>Live signing unavailable: trusted native enrollment required.</Text>
              </View>
            ))}
          </View>
        ) : null}

        <View style={styles.card}>
          <Text style={styles.cardTitle}>Local software-key diagnostic</Text>
          <Text style={styles.copy}>
            Policy: software explicitly allowed; biometric only; device-passcode fallback disabled.
            The resulting signature asserts neither WebAuthn user presence nor user verification and
            cannot satisfy a Class-A verifier.
          </Text>
          <Pressable style={styles.secondaryBtn} disabled={busy !== null} onPress={runLocalSoftwareCheck}>
            <Text style={styles.secondaryText}>{busy === 'software' ? 'Signing…' : 'Run local diagnostic'}</Text>
          </Pressable>
        </View>

        <Text style={styles.footer}>Assurance is server-derived from trusted enrollment evidence.</Text>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: '#0b0b0c' },
  content: { paddingHorizontal: 20, paddingBottom: 24 },
  title: { color: '#f5c451', fontSize: 26, fontWeight: '700', marginTop: 12 },
  subtitle: { color: '#9aa0a6', fontSize: 14, marginBottom: 16 },
  warning: { backgroundColor: '#241d10', borderColor: '#6f5520', borderWidth: 1, borderRadius: 12, padding: 16, marginBottom: 14 },
  warningTitle: { color: '#f5c451', fontSize: 16, fontWeight: '700', marginBottom: 6 },
  sectionTitle: { color: '#f4f5f6', fontSize: 18, fontWeight: '700', marginVertical: 12 },
  card: { backgroundColor: '#161719', borderRadius: 14, padding: 18, marginBottom: 14, borderWidth: 1, borderColor: '#26282b' },
  cardTitle: { color: '#f4f5f6', fontSize: 17, fontWeight: '600', marginBottom: 6 },
  copy: { color: '#aeb3b9', fontSize: 14, lineHeight: 20 },
  meta: { color: '#8fd19e', fontSize: 13, marginTop: 5 },
  field: { color: '#d4d7da', fontSize: 13, marginTop: 4 },
  input: { color: '#f4f5f6', borderColor: '#3a3d42', borderWidth: 1, borderRadius: 9, paddingHorizontal: 12, paddingVertical: 11, marginVertical: 12, letterSpacing: 1.5 },
  btn: { backgroundColor: '#f5c451', borderRadius: 10, paddingVertical: 13, alignItems: 'center' },
  btnText: { color: '#0b0b0c', fontWeight: '700', fontSize: 14 },
  secondaryBtn: { borderColor: '#777d85', borderWidth: 1, borderRadius: 10, paddingVertical: 12, alignItems: 'center', marginTop: 12 },
  secondaryText: { color: '#e1e3e5', fontWeight: '600', fontSize: 14 },
  row: { flexDirection: 'row', gap: 10, marginTop: 12 },
  rowButton: { flex: 1, marginTop: 0 },
  disabled: { color: '#d49a75', fontSize: 12, marginTop: 12 },
  empty: { color: '#6b7177', textAlign: 'center', marginBottom: 14 },
  footer: { color: '#6b7177', fontSize: 11, textAlign: 'center', paddingVertical: 8 },
});
