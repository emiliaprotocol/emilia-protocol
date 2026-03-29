'use client';

import { Player } from '@remotion/player';
import { TechStackComposition } from './TechStackAnimation';

export default function HeroAnimation() {
  return (
    <Player
      component={TechStackComposition}
      compositionWidth={600}
      compositionHeight={450}
      durationInFrames={360}
      fps={30}
      loop
      autoPlay
      style={{
        width: '100%',
        aspectRatio: '600 / 450',
        borderRadius: 4,
        border: '1px solid #E7E5E4',
        background: '#FAFAF9',
      }}
      controls={false}
      showPosterWhenPaused={false}
      inputProps={{}}
    />
  );
}
