-- EP Assurance Enum Alignment — Add 'medium' to allowed assurance levels
-- Aligns DB constraint with code: low, medium, substantial, high

-- Drop existing constraint if any (safe if none exists)
ALTER TABLE handshake_parties
  DROP CONSTRAINT IF EXISTS handshake_parties_assurance_level_check;

-- Add the aligned constraint
ALTER TABLE handshake_parties
  ADD CONSTRAINT handshake_parties_assurance_level_check
  CHECK (assurance_level IS NULL OR assurance_level IN ('low', 'medium', 'substantial', 'high'));
