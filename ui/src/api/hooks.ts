import { QueryClient, useQuery } from "@tanstack/react-query";
import { ApiError, api } from "./client";
import { LAKE_FIELDS } from "@/lib/fields";
import type { QueryField } from "./types";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 4000,
      refetchOnWindowFocus: false,
      retry: (count, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && count < 1
    }
  }
});

export const qk = {
  health: ["health"] as const,
  sources: ["sources"] as const,
  sourceHealth: (id: string) => ["source-health", id] as const,
  ledger: ["ledger"] as const,
  segments: ["segments"] as const,
  detections: ["detections"] as const,
  benchmark: ["benchmark"] as const,
  clusters: ["clusters"] as const,
  event: (id: string) => ["event", id] as const,
  raw: (id: string) => ["raw", id] as const,
  explain: (id: string) => ["explain", id] as const,
  fields: ["fields"] as const
};

export const useHealth = () =>
  useQuery({ queryKey: qk.health, queryFn: ({ signal }) => api.health(signal), refetchInterval: 5000, retry: false, staleTime: 0 });
export const useSources = () => useQuery({ queryKey: qk.sources, queryFn: api.sources, refetchInterval: 5000 });
export const useSourceHealth = (id: string | null) =>
  useQuery({ queryKey: qk.sourceHealth(id ?? ""), queryFn: () => api.sourceHealth(id!), enabled: !!id, refetchInterval: 5000 });
export const useLedger = () => useQuery({ queryKey: qk.ledger, queryFn: api.ledger, refetchInterval: 3000 });
export const useSegments = () => useQuery({ queryKey: qk.segments, queryFn: api.segments, refetchInterval: 10_000 });
export const useDetections = () => useQuery({ queryKey: qk.detections, queryFn: api.detections, refetchInterval: 15_000 });
export const useBenchmark = () => useQuery({ queryKey: qk.benchmark, queryFn: api.benchmark, retry: false });
export const useClusters = () => useQuery({ queryKey: qk.clusters, queryFn: api.clusters, refetchInterval: 15_000 });
export const useEvent = (id: string) => useQuery({ queryKey: qk.event(id), queryFn: () => api.event(id), staleTime: Infinity });
export const useExplain = (id: string, enabled = true) =>
  useQuery({ queryKey: qk.explain(id), queryFn: () => api.explain(id), staleTime: Infinity, retry: false, enabled });

/** Field whitelist for the query bar: server list if offered, else the frozen lake schema. */
export function useQueryFields(): QueryField[] {
  const q = useQuery({ queryKey: qk.fields, queryFn: api.fields, staleTime: Infinity, retry: false });
  return q.data?.fields?.length ? q.data.fields : LAKE_FIELDS;
}
