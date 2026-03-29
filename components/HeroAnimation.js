'use client';

import { Player } from '@remotion/player';
import { TechStackComposition } from './TechStackAnimation';

export default function HeroAnimation() {
  return (
    <div style={{ width: '100%' }}>
      <Player
        component={TechStackComposition}
        compositionWidth={640}
        compositionHeight={400}
        durationInFrames={360}
        fps={30}
        loop
        autoPlay
        style={{
          width: '100%',
          aspectRatio: '640 / 400',
          borderRadius: 4,
          border: '1px solid #E7E5E4',
          background: '#FAFAF9',
        }}
        controls={false}
        showPosterWhenPaused={false}
        inputProps={{}}
      />
    </div>
  );
}
