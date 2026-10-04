/** Stable identity colours (categorical slots c1..c8 in styles/index.css; order is fixed, never cycled by rank). */
function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}
export const sourceSlot = (id: string) => (hash(id) % 8) + 1;
export const sourceColor = (id: string) => `rgb(var(--c${sourceSlot(id)}))`;

/** Distinct hue per highlighted field (golden-angle walk) used for byte spans <-> tree rows. */
export function spanColors(index: number): { solid: string; tint: string; strong: string } {
  const h = Math.round((index * 137.508 + 195) % 360);
  return {
    solid: `hsl(${h} 78% 64%)`,
    tint: `hsl(${h} 78% 60% / 0.16)`,
    strong: `hsl(${h} 78% 60% / 0.38)`
  };
}
