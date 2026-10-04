import { lazy, Suspense } from "react";
import { Shell } from "@/components/Shell";
import { Skeleton } from "@/components/ui/primitives";
import { useRoute } from "@/lib/router";
import { BenchmarkPage } from "@/pages/Benchmark";
import { DetectionsPage } from "@/pages/Detections";
import { EventDetailPage } from "@/pages/EventDetail";
import { ExplorerPage } from "@/pages/Explorer";
import { IntegrityPage } from "@/pages/Integrity";
import { LivePage } from "@/pages/Live";
import { SourcesPage } from "@/pages/Sources";

// Monaco is large; only pay for it when Onboarding Studio is opened.
const StudioPage = lazy(() => import("@/pages/Studio"));

export function App() {
  const route = useRoute();
  const [root, id] = route.segments;
  let page;
  switch (root ?? "live") {
    case "explorer": page = <ExplorerPage key={route.params.toString()} route={route} />; break;
    case "event": page = <EventDetailPage key={id} id={id ?? ""} />; break;
    case "sources": page = <SourcesPage />; break;
    case "studio": page = (
      <Suspense fallback={<div className="p-8 space-y-3"><Skeleton className="h-8 w-64" /><Skeleton className="h-96" /></div>}><StudioPage /></Suspense>
    ); break;
    case "integrity": page = <IntegrityPage />; break;
    case "detections": page = <DetectionsPage />; break;
    case "benchmark": page = <BenchmarkPage />; break;
    default: page = <LivePage />;
  }
  return <Shell>{page}</Shell>;
}
