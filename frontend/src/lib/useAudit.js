import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient } from '../api/client';
import { markRemediated } from '../utils/history';
import { itemKey } from './domain';

const planItem = (plan, key) =>
  (plan?.devices || []).flatMap((d) => d.remediations).find((r) => itemKey(r.config_index, r.rule_id) === key) || null;

// A per-item fix outcome replaces that item in the plan, so every page keeps reading one source
const withItem = (plan, res) => plan && {
  ...plan,
  devices: plan.devices.map((d) => ({
    ...d,
    remediations: d.remediations.map((r) => (itemKey(r.config_index, r.rule_id) === itemKey(res.config_index, res.rule_id) ? { ...r, ...res } : r)),
  })),
};

// The audit's shared backend state: the remediation plan, the review queue, and the fixes applied this session.
// Overview, Fix, Teach and the finding drawer all read it, so their counts can never disagree.
export function useAudit(scan, revision, onScanExpired) {
  const scanId = scan?.scan_id;
  const [plan, setPlan] = useState(null);
  const [planLoading, setPlanLoading] = useState(false);
  const [planError, setPlanError] = useState(null);
  const [queue, setQueue] = useState(null);
  const [queueError, setQueueError] = useState(null);
  const [applied, setApplied] = useState(() => new Set());
  const [verified, setVerified] = useState({});
  // The inputs the displayed plan was generated (and verified) with: the only inputs a fix or download may use
  const inputs = useRef({});
  const loadedFor = useRef(null);
  const expiredRef = useRef(onScanExpired);
  expiredRef.current = onScanExpired;

  const expired = (err) => {
    if (err?.status !== 404) return false;
    expiredRef.current?.(scanId);
    return true;
  };

  const fetchPlan = useCallback(async (values) => {
    setPlanLoading(true);
    setPlanError(null);
    try {
      const next = await apiClient.getRemediationPlan(scanId, values);
      setPlan(next);
      inputs.current = values;
      return next;
    } finally {
      setPlanLoading(false);
    }
  }, [scanId]);

  const loadPlan = useCallback(async (values = inputs.current) => {
    try {
      return await fetchPlan(values);
    } catch (err) {
      if (!expired(err)) setPlanError(err.message);
      return null;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fetchPlan]);

  const loadQueue = useCallback(async () => {
    try {
      const [provisional, legacy] = await Promise.all([
        apiClient.getProvisionalResults(scanId),
        apiClient.getReviewQueue(scanId, false),
      ]);
      setQueue({ provisional: provisional.items, legacyPending: legacy.items.filter((i) => i.review_status === 'pending').length });
      setQueueError(null);
    } catch (err) {
      if (!expired(err)) setQueueError(err.message);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  // A new scan starts clean
  useEffect(() => {
    setPlan(null);
    setQueue(null);
    setApplied(new Set());
    setVerified({});
    inputs.current = {};
  }, [scanId]);

  // Generating a plan regenerates and rescans every fix: once per scan state (StrictMode runs effects twice)
  const stateKey = `${scanId}:${revision}`;
  useEffect(() => {
    if (!scanId || loadedFor.current === stateKey) return;
    loadedFor.current = stateKey;
    loadPlan();
    loadQueue();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stateKey]);

  const markApplied = useCallback((keys) => setApplied((prev) => new Set([...prev, ...keys])), []);

  // Generate and verify one fix on its own; "applied" only when the backend's rescan verified it
  const fixOne = async (item) => {
    const res = await apiClient.getRemediation(scanId, item.controlId, item.primary.device_hostname, item.configIndex, inputs.current);
    setVerified((v) => ({ ...v, [item.key]: res }));
    setPlan((p) => withItem(p, res));
    if (res.status === 'fixed') markApplied([item.key]);
    return res;
  };

  // Regenerate the plan with the values a fix needs; errors are thrown to the form that asked
  const answer = async (item, values) => {
    const next = await fetchPlan({ ...inputs.current, ...values });
    const res = planItem(next, item.key);
    if (res) setVerified((v) => ({ ...v, [item.key]: res }));
    if (res?.status === 'fixed') markApplied([item.key]);
    return res;
  };

  const download = async () => {
    await apiClient.downloadFixedConfigs(scanId, inputs.current);
    markRemediated(scanId);
  };

  return {
    plan, planLoading, planError, loadPlan, queue, queueError, loadQueue,
    applied, markApplied, verified, fixOne, answer, download,
  };
}
