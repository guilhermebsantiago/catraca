// Lays out a JSON value for a code panel. Only whitespace differs from the
// recorded answer: keys keep their order, values their text. Small members
// may share a line, single-member wrappers open on one line ({"decision": {),
// and lines too long for the panel wrap softly, as in an editor.

export type TokenKind = 'key' | 'str' | 'num' | 'lit' | 'punct';

export type Token = {text: string; kind: TokenKind; key?: string};

export type Line = {indent: number; tokens: Token[]; keys: string[]; cont?: boolean};

export type Layout = {
	width: number; // characters per line
	// Keys whose scalar members may share a line with their neighbors.
	pack?: string[];
	indent?: number; // spaces per level
};

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function scalar(v: unknown, key?: string): Token {
	if (typeof v === 'string') return {text: JSON.stringify(v), kind: 'str', key};
	if (typeof v === 'number') return {text: String(v), kind: 'num', key};
	return {text: JSON.stringify(v), kind: 'lit', key};
}

// The value on one line, or null when it does not fit or is not simple.
function inline(v: unknown, key?: string): Token[] {
	if (Array.isArray(v)) {
		const out: Token[] = [{text: '[', kind: 'punct'}];
		v.forEach((x, i) => {
			if (i) out.push({text: ', ', kind: 'punct'});
			out.push(...inline(x, key));
		});
		out.push({text: ']', kind: 'punct'});
		return out;
	}
	if (isObj(v)) {
		const out: Token[] = [{text: '{', kind: 'punct'}];
		Object.entries(v).forEach(([k, x], i) => {
			if (i) out.push({text: ', ', kind: 'punct'});
			out.push({text: JSON.stringify(k), kind: 'key', key: k}, {text: ': ', kind: 'punct'}, ...inline(x, k));
		});
		out.push({text: '}', kind: 'punct'});
		return out;
	}
	return [scalar(v, key)];
}

const width = (ts: Token[]) => ts.reduce((n, t) => n + t.text.length, 0);

export function layout(value: unknown, o: Layout): Line[] {
	const step = o.indent ?? 2;
	const pack = new Set(o.pack ?? []);
	const lines: Line[] = [];
	const push = (indent: number, tokens: Token[]) =>
		lines.push({indent, tokens, keys: tokens.filter((t) => t.key).map((t) => t.key!)});

	// Writes v after prefix (already on the current line), closing with
	// suffix (such as a comma).
	function emit(v: unknown, indent: number, prefix: Token[], suffix: Token[], key?: string) {
		const nested = (x: unknown) => isObj(x) || (Array.isArray(x) && x.some((y) => isObj(y) || Array.isArray(y)));
		const one = [...prefix, ...inline(v, key), ...suffix];
		const fits = indent * step + width(one) <= o.width;
		const small = isObj(v) && Object.keys(v).length <= 3 && !Object.values(v).some(nested);
		if (!nested(v) || (indent > 0 && small && fits)) {
			push(indent, one);
			return;
		}
		if (Array.isArray(v)) {
			if (v.length === 1 && isObj(v[0])) {
				// [{ ... }]
				members(v[0], indent, [...prefix, {text: '[{', kind: 'punct'}], [{text: '}]', kind: 'punct'}, ...suffix]);
				return;
			}
			push(indent, [...prefix, {text: '[', kind: 'punct'}]);
			v.forEach((x, i) => emit(x, indent + 1, [], i < v.length - 1 ? [{text: ',', kind: 'punct'}] : []));
			push(indent, [{text: ']', kind: 'punct'}, ...suffix]);
			return;
		}
		const obj = v as Record<string, unknown>;
		const entries = Object.entries(obj);
		if (entries.length === 1 && isObj(entries[0][1])) {
			// {"decision": { ... }}
			const [k, x] = entries[0];
			members(
				x as Record<string, unknown>,
				indent,
				[...prefix, {text: '{', kind: 'punct'}, {text: JSON.stringify(k), kind: 'key', key: k}, {text: ': {', kind: 'punct'}],
				[{text: '}}', kind: 'punct'}, ...suffix],
			);
			return;
		}
		members(obj, indent, [...prefix, {text: '{', kind: 'punct'}], [{text: '}', kind: 'punct'}, ...suffix]);
	}

	function members(obj: Record<string, unknown>, indent: number, open: Token[], close: Token[]) {
		push(indent, open);
		const entries = Object.entries(obj);
		let i = 0;
		while (i < entries.length) {
			const [k, x] = entries[i];
			const last = i === entries.length - 1;
			const isScalarLike = !isObj(x) && !(Array.isArray(x) && x.some((y) => isObj(y)));
			// A decision's own action keeps its line; a match's may share one.
			const packable = (key: string) => pack.has(key) && !(key === 'action' && indent < 1);
			if (packable(k) && isScalarLike) {
				// Pack this and the following packable members while they fit.
				let line: Token[] = [];
				let j = i;
				while (j < entries.length) {
					const [kj, xj] = entries[j];
					const ok = packable(kj) && !isObj(xj) && !(Array.isArray(xj) && xj.some((y) => isObj(y)));
					if (!ok) break;
					const member: Token[] = [{text: JSON.stringify(kj), kind: 'key', key: kj}, {text: ': ', kind: 'punct'}, ...inline(xj, kj)];
					const sep: Token[] = line.length ? [{text: ' ', kind: 'punct'}] : [];
					const comma: Token[] = j < entries.length - 1 ? [{text: ',', kind: 'punct'}] : [];
					if (line.length && (indent + 1) * step + width([...line, ...sep, ...member, ...comma]) > o.width) break;
					line = [...line, ...sep, ...member, ...comma];
					j++;
				}
				push(indent + 1, line);
				i = j;
				continue;
			}
			emit(x, indent + 1, [{text: JSON.stringify(k), kind: 'key', key: k}, {text: ': ', kind: 'punct'}], last ? [] : [{text: ',', kind: 'punct'}], k);
			i++;
		}
		push(indent, close);
	}

	emit(value, 0, [], []);
	return wrap(lines, o.width, step);
}

// Soft-wraps lines longer than the width at a space inside a string, with
// continuation lines indented two levels.
function wrap(lines: Line[], max: number, step: number): Line[] {
	const out: Line[] = [];
	for (const line of lines) {
		let cur = line;
		for (let guard = 0; guard < 8; guard++) {
			const lead = cur.indent * step;
			// A trailing comma or bracket may overhang by a character or two
			// rather than wrap alone.
			const last = cur.tokens[cur.tokens.length - 1];
			const overhang = last && last.kind === 'punct' ? Math.min(2, last.text.length) : 0;
			if (lead + width(cur.tokens) <= max + overhang) break;
			// Find the split point.
			let col = lead;
			let split: {ti: number; at: number} | null = null;
			for (let ti = 0; ti < cur.tokens.length; ti++) {
				const tk = cur.tokens[ti];
				if (col + tk.text.length > max) {
					if (tk.kind === 'str') {
						// After a space, or after a slash in a URL or path.
						const room = max - col;
						const at = Math.max(tk.text.lastIndexOf(' ', room - 1), tk.text.lastIndexOf('/', room - 1));
						if (at > 0) split = {ti, at: at + 1};
					}
					if (!split && ti > 0) split = {ti, at: 0};
					break;
				}
				col += tk.text.length;
			}
			if (!split) break;
			const head = cur.tokens.slice(0, split.ti);
			const tail = cur.tokens.slice(split.ti + 1);
			const tk = cur.tokens[split.ti];
			if (split.at > 0) head.push({...tk, text: tk.text.slice(0, split.at)});
			const rest = split.at > 0 ? [{...tk, text: tk.text.slice(split.at)}, ...tail] : [tk, ...tail];
			out.push({...cur, tokens: head, keys: cur.keys});
			cur = {indent: (line.cont ? cur.indent : line.indent) + 2, tokens: rest, keys: cur.keys, cont: true};
		}
		out.push(cur);
	}
	return out;
}
