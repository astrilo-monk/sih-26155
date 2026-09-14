import { useEffect, useRef, useState } from 'react';

// Hash routing: "#/" is the public site, "#/app/…" the application. No router dependency is needed for this.
const readHash = () => window.location.hash.replace(/^#/, '') || '/';

export function useHashRoute() {
  const [path, setPath] = useState(readHash);
  useEffect(() => {
    const onChange = () => setPath(readHash());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return path;
}

export function navigate(path) {
  if (readHash() !== path) window.location.hash = path;
}

// Motion runs only when the browser can confirm the user has not asked for reduced motion. Everywhere else
// (reduced motion, tests, browsers without matchMedia) components render their final, real state at once.
export function motionAllowed() {
  return typeof window !== 'undefined'
    && typeof window.matchMedia === 'function'
    && typeof requestAnimationFrame === 'function'
    && !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

export const prefersReducedMotion = () => !motionAllowed();

// Adds .is-visible to every .reveal inside the returned ref once it scrolls into view
export function useReveal() {
  const ref = useRef(null);
  useEffect(() => {
    const els = ref.current?.querySelectorAll('.reveal') || [];
    if (typeof IntersectionObserver === 'undefined' || !motionAllowed()) {
      els.forEach((el) => el.classList.add('is-visible'));
      return undefined;
    }
    const io = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          io.unobserve(entry.target);
        }
      });
    }, { rootMargin: '0px 0px -8% 0px' });
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);
  return ref;
}

// True once the element has been seen (immediately when motion is not allowed)
export function useInView(threshold = 0.3) {
  const ref = useRef(null);
  const [seen, setSeen] = useState(() => !motionAllowed());
  useEffect(() => {
    if (seen) return undefined;
    const el = ref.current;
    if (!el || typeof IntersectionObserver === 'undefined') {
      setSeen(true);
      return undefined;
    }
    const io = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        setSeen(true);
        io.disconnect();
      }
    }, { threshold });
    io.observe(el);
    return () => io.disconnect();
  }, [seen, threshold]);
  return [ref, seen];
}

// Steps through `count` stages once `active`: returns how many are on, and a replay function.
// Without motion every stage is on from the first render.
export function useSequence(count, { stepMs = 520, startDelay = 200, active = true } = {}) {
  const [on, setOn] = useState(() => (motionAllowed() ? 0 : count));
  const [run, setRun] = useState(0);
  useEffect(() => {
    if (!active) return undefined;
    if (!motionAllowed()) {
      setOn(count);
      return undefined;
    }
    setOn(0);
    const timers = Array.from({ length: count }, (_, i) => setTimeout(() => setOn(i + 1), startDelay + i * stepMs));
    return () => timers.forEach(clearTimeout);
  }, [active, count, stepMs, startDelay, run]);
  return [on, () => setRun((r) => r + 1)];
}

// 0..1: how far the element has scrolled through the lower part of the viewport (1 without motion)
export function useScrollProgress() {
  const ref = useRef(null);
  const [progress, setProgress] = useState(() => (motionAllowed() ? 0 : 1));
  useEffect(() => {
    if (!motionAllowed()) {
      setProgress(1);
      return undefined;
    }
    let raf = 0;
    const update = () => {
      raf = 0;
      const el = ref.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const start = window.innerHeight * 0.85;
      const span = Math.max(rect.height, window.innerHeight * 0.45);
      setProgress(Math.min(1, Math.max(0, (start - rect.top) / span)));
    };
    const onScroll = () => { if (!raf) raf = requestAnimationFrame(update); };
    update();
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll);
    return () => {
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('resize', onScroll);
      cancelAnimationFrame(raf);
    };
  }, []);
  return [ref, progress];
}

// False for the first painted frame, then true: lets a bar grow from 0 to its real width
export function useEntered() {
  const [entered, setEntered] = useState(() => !motionAllowed());
  useEffect(() => {
    if (entered) return undefined;
    let inner;
    const outer = requestAnimationFrame(() => { inner = requestAnimationFrame(() => setEntered(true)); });
    return () => {
      cancelAnimationFrame(outer);
      cancelAnimationFrame(inner);
    };
  }, [entered]);
  return entered;
}

// Animates to `value` (from `from` on mount, from the last shown value on change). Without motion: `value` at once.
export function useAnimatedNumber(value, { from, duration = 320 } = {}) {
  const initial = from != null && value != null && motionAllowed() ? from : value;
  const [shown, setShown] = useState(initial);
  const current = useRef(initial);
  useEffect(() => {
    const a = current.current;
    if (value == null || a == null || a === value || !motionAllowed()) {
      current.current = value;
      setShown(value);
      return undefined;
    }
    const t0 = performance.now();
    let raf;
    const step = (t) => {
      const k = Math.min(1, Math.max(0, (t - t0) / duration));
      const v = Math.round(a + (value - a) * (1 - (1 - k) ** 3));
      current.current = v;
      setShown(v);
      if (k < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [value, duration]);
  return shown;
}
