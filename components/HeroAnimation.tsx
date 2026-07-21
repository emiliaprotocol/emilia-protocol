'use client';

import { Player } from '@remotion/player';
import { TechStackComposition } from './TechStackAnimation';

type Props = Record<string, never>;

export default function HeroAnimation({}: Props) {
  return (
    <Player
      component={TechStackComposition}
      compositionWidth={600}
      compositionHeight={560}
      durationInFrames={360}
      fps={30}
      loop
      autoPlay
      style={{
        width: '100%',
        aspectRatio: '600 / 560',
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
