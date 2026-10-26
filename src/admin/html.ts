// The only place admin pages turn values into HTML. Everything interpolated into an html``
// template is escaped unless it is itself an Html fragment, so guardian- or agent-derived
// text can't become markup by forgetting to escape it.

export class Html {
  constructor(readonly value: string) {}
}

type Part = Html | string | number | boolean | null | undefined | readonly Part[];

const ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => ESCAPES[c]!);
}

function render(part: Part): string {
  if (part instanceof Html) return part.value;
  if (Array.isArray(part)) return part.map(render).join('');
  if (part === null || part === undefined) return '';
  return escapeHtml(String(part));
}

export function html(strings: TemplateStringsArray, ...parts: Part[]): Html {
  let out = strings[0]!;
  parts.forEach((part, i) => {
    out += render(part) + strings[i + 1]!;
  });
  return new Html(out);
}
