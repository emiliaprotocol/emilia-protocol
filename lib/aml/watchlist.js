/**
 * AML watchlist — bundled SNAPSHOT.
 *
 * This is a small, SYNTHETIC snapshot in the shape of an OFAC SDN /
 * consolidated-list record. It exists so the screening logic in screening.js is
 * exercised deterministically and ships with a working default. It is NOT the
 * real sanctions list.
 *
 * In production, an operations job refreshes the watchlist from the official
 * feeds (OFAC SDN + consolidated, EU consolidated, UN consolidated) and supplies
 * it via screenSanctions({ list }). The schema below is the contract that feed
 * must produce.
 *
 *   { name, type:'individual'|'entity'|'vessel', program, list, aliases:[] }
 *
 * @license Apache-2.0
 */

export const SANCTIONS_SNAPSHOT = Object.freeze([
  {
    name: 'BLOCKED PERSON ALPHA',
    type: 'individual',
    program: 'SDGT',
    list: 'SNAPSHOT-SYNTHETIC',
    aliases: ['ALPHA BLOCKED', 'A. BLOCKED PERSON'],
  },
  {
    name: 'SANCTIONED TRADING COMPANY LLC',
    type: 'entity',
    program: 'IRAN-EO13902',
    list: 'SNAPSHOT-SYNTHETIC',
    aliases: ['SANCTIONED TRADING CO', 'STC LLC'],
  },
  {
    name: 'EMBARGOED SHIPPING GROUP',
    type: 'entity',
    program: 'DPRK',
    list: 'SNAPSHOT-SYNTHETIC',
    aliases: ['EMBARGOED SHIPPING'],
  },
  {
    name: 'BLOCKED VESSEL HORIZON',
    type: 'vessel',
    program: 'DPRK',
    list: 'SNAPSHOT-SYNTHETIC',
    aliases: [],
  },
]);

/**
 * Watchlist loader / injection point. Returns the bundled snapshot today; an
 * operations refresh replaces this with the official feed.
 */
export function loadWatchlist() {
  return SANCTIONS_SNAPSHOT;
}
