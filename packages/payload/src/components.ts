import { Button } from '@payloadcms/ui';
import { createElement } from 'react';

// Payload owns the button typography, theme, border, radius and interaction states.
const buttonStyles = `
.xignet-login .xignet-login__button { width: 100%; }
.xignet-login__content { display: flex; align-items: center; justify-content: center; gap: 12px; }
.xignet-login__mark { display: block; flex: none; width: 24px; height: 24px; }
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
          Button,
          {
            el: 'anchor',
            url: loginPath,
            buttonStyle: 'secondary',
            size: 'large',
            margin: false,
            className: 'xignet-login__button',
          },
          createElement(
            'span',
            { className: 'xignet-login__content' },
            createElement(
              'svg',
              {
                className: 'xignet-login__mark',
                viewBox: '0 0 560 560',
                fill: '#f17c72',
                'aria-hidden': true,
                focusable: false,
              },
              createElement('path', {
                d: 'M228 24C182 48 121 66 88 108C50 157 151 220 268 278L278 268C225 227 178 191 150 153C111 110 128 84 228 24Z',
              }),
              createElement('path', {
                transform: 'matrix(-1 0 0 1 560 0)',
                d: 'M228 24C182 48 121 66 88 108C50 157 151 220 268 278L278 268C225 227 178 191 150 153C111 110 128 84 228 24Z',
              }),
              createElement('path', {
                transform: 'matrix(1 0 0 -1 0 560)',
                d: 'M228 24C182 48 121 66 88 108C50 157 151 220 268 278L278 268C225 227 178 191 150 153C111 110 128 84 228 24Z',
              }),
              createElement('path', {
                transform: 'matrix(-1 0 0 -1 560 560)',
                d: 'M228 24C182 48 121 66 88 108C50 157 151 220 268 278L278 268C225 227 178 191 150 153C111 110 128 84 228 24Z',
              }),
              createElement('path', {
                d: 'M88 108C8 202 8 358 88 452C24 354 24 206 88 108Z',
              }),
              createElement('path', {
                transform: 'matrix(-1 0 0 1 560 0)',
                d: 'M88 108C8 202 8 358 88 452C24 354 24 206 88 108Z',
              }),
            ),
            createElement('span', null, text),
          ),
        ),
      )
    : createElement('p', null, 'Xignet sign-in is not enabled.');
}
