'use client';

import { Player } from '@remotion/player';
import { TechStackComposition } from './TechStackAnimation';

export default function HeroAnimation() {
  return (
    <div style={{ width: '100%', maxWidth: 560, margin: '0 auto' }}>
      <Player
        component={TechStackComposition}
        compositionWidth={560}
        compositionHeight={240}
        durationInFrames={180}
        fps={30}
        loop
        autoPlay
        style={{
          width: '100%',
          aspectRatio: '560 / 240',
          borderRadius: 8,
          border: '1px solid rgba(255,255,255,0.06)',
          background: 'rgba(15,23,42,0.5)',
        }}
        controls={false}
        showPosterWhenPaused={false}
        inputProps={{}}
      />
    </div>
  );
}
