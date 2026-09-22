import { useAnimatedNumber } from '../../lib/hooks';

// Counts to a value the report already holds -never a placeholder. Without motion it shows the value at once.
export default function Count({ value, from = 0, duration = 360 }) {
  const shown = useAnimatedNumber(value, { from, duration });
  return <>{value == null ? '-' : shown}</>;
}
