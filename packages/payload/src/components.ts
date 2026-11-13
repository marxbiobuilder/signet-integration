import { createElement } from 'react';

const buttonStyles = `
.signet-btn {
  box-sizing: border-box;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  height: 40px;
  padding: 0 12px;
  border: 1px solid var(--signet-btn-border);
  border-radius: 8px;
  background: var(--signet-btn-bg);
  color: var(--signet-btn-text);
  font: 500 14px/1 Inter, ui-sans-serif, system-ui, -apple-system, "Noto Sans TC", "Microsoft JhengHei", sans-serif;
  letter-spacing: .01em;
  white-space: nowrap;
  text-decoration: none;
  cursor: pointer;
  -webkit-tap-highlight-color: transparent;
  transition: background-color .15s, border-color .15s;
}
.signet-btn:hover { background: var(--signet-btn-bg-hover); border-color: var(--signet-btn-border-hover); }
.signet-btn:active { background: var(--signet-btn-bg-active); }
.signet-btn:focus-visible { outline: 2px solid var(--signet-btn-focus); outline-offset: 2px; }
.signet-btn--light {
  --signet-btn-bg: #ffffff;
  --signet-btn-bg-hover: #fbf5f4;
  --signet-btn-bg-active: #f4e9e7;
  --signet-btn-border: #8a807d;
  --signet-btn-border-hover: #6b625f;
  --signet-btn-text: #1f1d1c;
  --signet-btn-icon: #c0332c;
  --signet-btn-focus: #c93630;
}
html[data-theme="dark"] .xignet-login .signet-btn {
  --signet-btn-bg: #1a1d23;
  --signet-btn-bg-hover: #23262d;
  --signet-btn-bg-active: #2a2d35;
  --signet-btn-border: #737a86;
  --signet-btn-border-hover: #a6acb8;
  --signet-btn-text: #f5f6f8;
  --signet-btn-icon: #f17c72;
  --signet-btn-focus: #f58b82;
}
.signet-btn__mark { flex: none; width: 22px; height: 22px; }
.signet-btn__orbit { fill: none; stroke: var(--signet-btn-icon); stroke-width: 1.6; stroke-linecap: round; stroke-linejoin: round; }
.xignet-login .signet-btn { width: 100%; }
@media (prefers-reduced-motion: reduce) { .signet-btn { transition: none; } }
`;

/** Server component; configuration contains only display data, never secrets. */
export function XignetLogin({
  enabled,
  loginPath,
  label,
  i18n,
}: {
  enabled: boolean;
  loginPath: string;
  label: string | Readonly<Record<string, string>>;
  i18n?: { language?: string };
}) {
  const language = i18n?.language ?? 'en';
  const text =
    typeof label === 'string'
      ? label
      : (label[language] ??
        label[language.split('-')[0]!] ??
        label.en ??
        'Sign in with Xignet');
  return enabled
    ? createElement(
        'div',
        { className: 'xignet-login', style: { marginBottom: '1.5rem' } },
        createElement('style', null, buttonStyles),
        createElement(
          'a',
          { className: 'signet-btn signet-btn--light', href: loginPath },
          createElement(
            'svg',
            {
              className: 'signet-btn__mark',
              viewBox: '0 0 24 24',
              'aria-hidden': true,
              focusable: false,
            },
            createElement(
              'g',
              { className: 'signet-btn__orbit' },
              createElement('circle', { cx: 12, cy: 12, r: 6 }),
              createElement('ellipse', {
                cx: 12,
                cy: 12,
                rx: 11,
                ry: 4,
                transform: 'rotate(-35 12 12)',
              }),
              createElement('path', { d: 'M12 6v12M6 12h12' }),
            ),
          ),
          createElement('span', null, text),
        ),
      )
    : createElement('p', null, 'Xignet sign-in is not enabled.');
}
