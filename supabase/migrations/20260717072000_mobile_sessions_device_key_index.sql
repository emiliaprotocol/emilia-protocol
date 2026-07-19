-- SPDX-License-Identifier: Apache-2.0
-- Cover the enrollment foreign key used during device revocation and deletion.

create index if not exists mobile_sessions_entity_device_idx
  on mobile_sessions (entity_ref, device_key_id);
