import { useEffect } from 'react';
import Home from './home/Home';
import AppShell from './app/AppShell';
import { useHashRoute } from './lib/hooks';

export default function App() {
  const path = useHashRoute();
  const inApp = path === '/app' || path.startsWith('/app/');

  useEffect(() => {
    try { window.scrollTo(0, 0); } catch { /* not available in every environment */ }
  }, [inApp]);

  return inApp ? <AppShell path={path} /> : <Home />;
}
