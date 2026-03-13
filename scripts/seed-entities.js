#!/usr/bin/env node

/**
 * Seed script — register Rex (#1) and Ruby (#2) on the EMILIA Protocol.
 * 
 * Usage:
 *   node scripts/seed-entities.js https://emiliaprotocol.ai
 *   node scripts/seed-entities.js http://localhost:3000
 * 
 * This is idempotent — if they already exist, it prints their info.
 */

const BASE_URL = process.argv[2] || 'http://localhost:3000';

const entities = [
  {
    entity_id: 'rex-booking-v1',
    display_name: 'Rex — Inbound AI Receptionist',
    entity_type: 'agent',
    description: 'Handles inbound calls, texts, and web inquiries for service businesses. Qualifies leads and books appointments 24/7.',
    capabilities: ['inbound_booking', 'sms_reply', 'call_handling', 'lead_qualification', 'calendar_management'],
    category: 'receptionist',
    pricing_model: 'per_task',
    pricing_amount_cents: 25,
  },
  {
    entity_id: 'ruby-retention-v1',
    display_name: 'Ruby — Outbound Retention Agent',
    entity_type: 'agent',
    description: 'Re-engages dormant clients, past leads, and lapsed accounts via personalized outreach across SMS, email, and voice.',
    capabilities: ['outbound_sms', 'email_campaigns', 'voice_outreach', 'client_reengagement', 'churn_prevention'],
    category: 'retention',
    pricing_model: 'per_task',
    pricing_amount_cents: 15,
  },
];

async function seed() {
  console.log(`Seeding entities at ${BASE_URL}...\n`);

  for (const entity of entities) {
    try {
      const res = await fetch(`${BASE_URL}/api/entities/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(entity),
      });

      const data = await res.json();

      if (res.status === 201) {
        console.log(`Registered: ${entity.display_name}`);
        console.log(`  Entity ID: ${data.entity.entity_id}`);
        console.log(`  API Key:   ${data.api_key}`);
        console.log(`  IMPORTANT: Store this API key — it won't be shown again.\n`);
      } else if (res.status === 409) {
        console.log(`Already exists: ${entity.entity_id}`);
        console.log(`  ${data.error}\n`);
      } else {
        console.error(`Error registering ${entity.entity_id}:`, data);
      }
    } catch (err) {
      console.error(`Failed to register ${entity.entity_id}:`, err.message);
    }
  }

  console.log('Done. Rex is Entity #1. Ruby is Entity #2.');
}

seed();
