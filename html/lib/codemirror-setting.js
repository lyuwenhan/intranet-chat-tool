/*
 * Project: Intranet Chat Tool
 * Copyright (C) 2025 lyuwenhan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

DOMPurify.addHook('uponSanitizeAttribute', (node, data) => {
	if (data.attrName === 'style' && /position\s*:/.test(data.attrValue)) {
		data.keepAttr = false;
	}
});
MathJax = {
	tex: {
		packages: ['base'],        // extensions to use
		inlineMath: [              // start/end delimiter pairs for in-line math
		['$', '$'],
		],
		displayMath: [             // start/end delimiter pairs for display math
		['$$', '$$'],
		],
		processEscapes: true,      // use \$ to produce a literal dollar sign
		processEnvironments: true, // process \begin{xxx}...\end{xxx} outside math mode
		processRefs: true,         // process \ref{...} outside of math mode
		digits: /^(?:[0-9]+(?:\{,\}[0-9]{3})*(?:\.[0-9]*)?|\.[0-9]+)/,
								// pattern for recognizing numbers
		tags: 'none',              // or 'ams' or 'all'
		tagSide: 'right',          // side for \tag macros
		tagIndent: '0.8em',        // amount to indent tags
		useLabelIds: true,         // use label name rather than tag for ids
		maxMacros: 1000,           // maximum number of macro substitutions per expression
		maxBuffer: 5 * 1024,       // maximum size for the internal TeX string (5K)
	}
};