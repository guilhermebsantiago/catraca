import React from 'react';
import {ACTION_COLORS, Action, THEMES, Theme, clamp01, markPath} from '../brand';
import {GEOMETRY, Slot, dots, rotorAngle} from './sim';

export type LaneProps = {
	slots: Slot[];
	t: number; // ms on the lane's clock
	theme: Theme;
	ax: number; // rotor axis, px
	ay: number;
	m: number; // module, px
	width: number; // visible width, px (for culling)
	x0?: number; // left edge of the visible range, px
	rotorOpacity?: number;
	railFrom?: number; // px; where the rail starts and ends
	railTo?: number;
	bayLife?: number;
	// Rings to the right of this x (px) fade out: used when the rotor
	// first appears on a lane of undecided rings.
	dim?: (x: number) => number;
	// The throttle countdown label, such as "60s".
	countdownLabel?: string;
	labelFont?: string;
	labelSize?: number;
};

const fmt = (v: number) => Math.round(v * 100) / 100;

export const Lane: React.FC<LaneProps> = (p) => {
	const T = THEMES[p.theme];
	const C = ACTION_COLORS[p.theme];
	const {m, ax, ay} = p;
	const ly = ay + GEOMETRY.offset * m;
	const r = GEOMETRY.dot * m;
	const sw = Math.max(1.5, m * 0.08);
	const x0 = p.x0 ?? 0;
	const ds = dots(p.slots, p.t, {minX: (x0 - ax) / m - 1, maxX: (x0 + p.width - ax) / m + 1, bayLife: p.bayLife});
	const angle = rotorAngle(p.slots, p.t);
	const held = ds.filter((d) => d.held);
	const bayIn = held.length ? Math.max(...held.map((d) => clamp01(d.y / GEOMETRY.bayDrop) * d.opacity)) : 0;
	const colorOf = (a: Action | 'none') => (a === 'none' ? T.ring : C[a].mark);

	return (
		<g>
			<path
				stroke={T.rail}
				strokeWidth={Math.max(1, m * 0.05)}
				d={`M${fmt(p.railFrom ?? x0)} ${fmt(ly)}H${fmt(p.railTo ?? x0 + p.width)}`}
			/>
			{bayIn > 0 ? (
				<path
					stroke={T.rail}
					strokeWidth={Math.max(1, m * 0.05)}
					strokeLinecap="round"
					opacity={bayIn}
					d={`M${fmt(ax + (GEOMETRY.sector + 1.0) * m)} ${fmt(ly + GEOMETRY.bayDrop * m)}h${fmt(2.6 * m)}`}
				/>
			) : null}
			{ds.map((d) => {
				const cx = ax + d.x * m;
				const cy = ly + d.y * m;
				const dim = p.dim ? p.dim(cx) : 1;
				const op = d.opacity * dim;
				if (op <= 0.001) return null;
				const color = colorOf(d.action);
				const items: React.ReactNode[] = [];
				if (d.fill < 1) {
					items.push(
						<circle
							key="ring"
							cx={fmt(cx)}
							cy={fmt(cy)}
							r={fmt(r - sw / 2)}
							fill="none"
							stroke={T.ring}
							strokeWidth={fmt(sw)}
							opacity={1 - d.fill}
						/>,
					);
				}
				if (d.fill > 0) {
					items.push(<circle key="fill" cx={fmt(cx)} cy={fmt(cy)} r={fmt(r)} fill={color} opacity={d.fill} />);
				}
				if (d.shadow && d.shadowIn > 0) {
					const rr = r + 0.2 * m;
					const dash = (2 * Math.PI * rr) / 14;
					const on = dash * (0.55 + 0.45 * d.promoted);
					const off = dash * 0.45 * (1 - d.promoted);
					items.push(
						<circle
							key="shadow"
							cx={fmt(cx)}
							cy={fmt(cy)}
							r={fmt(rr * (0.8 + 0.2 * d.shadowIn))}
							fill="none"
							stroke={C[d.shadow].mark}
							strokeWidth={fmt(sw)}
							strokeDasharray={d.promoted >= 1 ? undefined : `${fmt(on)} ${fmt(off)}`}
							opacity={d.shadowIn}
						/>,
					);
				}
				if (d.countdown !== undefined) {
					// A thin ring counting down retry_after, linear.
					const rr = r + 0.2 * m;
					const len = 2 * Math.PI * rr;
					items.push(
						<circle
							key="countdown-track"
							cx={fmt(cx)}
							cy={fmt(cy)}
							r={fmt(rr)}
							fill="none"
							stroke={T.rail}
							strokeWidth={fmt(sw * 0.75)}
						/>,
						<circle
							key="countdown"
							cx={fmt(cx)}
							cy={fmt(cy)}
							r={fmt(rr)}
							fill="none"
							stroke={C.throttle.mark}
							strokeWidth={fmt(sw)}
							strokeDasharray={`${fmt(len * (1 - d.countdown))} ${fmt(len)}`}
							transform={`rotate(-90 ${fmt(cx)} ${fmt(cy)})`}
						/>,
					);
					if (p.countdownLabel) {
						items.push(
							<text
								key="countdown-label"
								x={fmt(cx + rr)}
								y={fmt(cy - rr - 0.5 * m)}
								textAnchor="end"
								fontFamily={p.labelFont}
								fontSize={fmt(p.labelSize ?? 0.42 * m)}
								fill={C.throttle.text}
							>
								{p.countdownLabel}
							</text>,
						);
					}
				}
				return (
					<g key={d.key} opacity={op}>
						{items}
					</g>
				);
			})}
			<g opacity={p.rotorOpacity ?? 1} transform={`rotate(${fmt(angle)} ${fmt(ax)} ${fmt(ay)})`}>
				<path fill={T.fg} d={markPath(ax, ay, m)} />
			</g>
		</g>
	);
};
