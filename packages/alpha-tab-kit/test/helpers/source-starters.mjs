import { readFileSync } from 'node:fs';
const guide = readFileSync(new URL('../../../../src/mcp/guides/app-builder-1.0.0.md', import.meta.url), 'utf8');
export const starters = [...guide.matchAll(/```html\n([\s\S]*?)```/g)].map((match, i) => ({
  name: ['recent-records', 'meeting-notes'][i], html: match[1],
  descriptor: { package: ['recent-records', 'meeting-notes'][i], version: '0.1.0',
    declaration: JSON.parse([...guide.matchAll(/```json\n([\s\S]*?)```/g)][i][1]) }
}));
