import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { NewHireStory } from '@/components/home/NewHireStory';

export default function HomePage(): React.ReactElement {
  return (
    <div>
      <SiteNav activePage="" />
      <main>
        <NewHireStory />
      </main>
      <SiteFooter />
    </div>
  );
}
