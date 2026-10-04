const P: Record<string, string> = {
  live: "M3 12h3l2-7 4 14 3-9 2 2h4",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14ZM20 20l-4-4",
  doc: "M7 3h7l5 5v13H7zM14 3v5h5M10 13h6M10 17h6",
  server: "M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01",
  wand: "M5 19 16 8M14 6l4 4M7 3v3M5.5 4.5h3M19 14v3M17.5 15.5h3",
  shield: "M12 3 4 6v6c0 4.5 3.3 8 8 9 4.7-1 8-4.5 8-9V6zM8.5 12l2.5 2.5L16 9.5",
  alert: "M12 4 3 20h18zM12 10v5M12 17.5v.01",
  gauge: "M4 17a8 8 0 1 1 16 0M12 17l4-6M7 17h.01M17 17h.01",
  check: "M5 12.5 10 17.5 19 7",
  x: "M6 6l12 12M18 6 6 18",
  play: "M8 5v14l11-7z",
  pause: "M8 5v14M16 5v14",
  download: "M12 4v11M7 11l5 5 5-5M5 20h14",
  copy: "M9 9h10v11H9zM5 15V4h10",
  link: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  chevR: "M9 6l6 6-6 6",
  chevD: "M6 9l6 6 6-6",
  refresh: "M20 11a8 8 0 0 0-14-4L4 9M4 4v5h5M4 13a8 8 0 0 0 14 4l2-2M20 20v-5h-5",
  plug: "M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0zM12 17v4",
  upload: "M12 16V5M7 9l5-5 5 5M5 20h14",
  filter: "M4 5h16l-6 8v6l-4-2v-4z",
  clock: "M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16ZM12 8v4l3 2",
  hash: "M5 9h14M5 15h14M10 4 8 20M16 4l-2 16",
  trash: "M5 7h14M10 7V4h4v3M7 7l1 13h8l1-13",
  drift: "M4 16c3 0 3-8 6-8s3 8 6 8 2-4 4-4",
  bolt: "M13 3 5 13h6l-1 8 8-10h-6z",
  layers: "M12 3 3 8l9 5 9-5zM3 13l9 5 9-5",
  book: "M5 4h10a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3zM5 17a3 3 0 0 1 3-3h10",
  eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12ZM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z"
};
export type IconName = keyof typeof P;

export function Icon({ name, size = 15, className, strokeWidth = 1.7 }: { name: IconName; size?: number; className?: string; strokeWidth?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={strokeWidth}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d={P[name]} />
    </svg>
  );
}
