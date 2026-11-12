import { createElement } from 'react';

/** Server component; configuration contains only display data, never secrets. */
export function XignetLogin({
  enabled,
  loginPath,
  label,
}: {
  enabled: boolean;
  loginPath: string;
  label: string;
}) {
  return enabled
    ? createElement(
        'div',
        { style: { marginBottom: '1.5rem' } },
        createElement(
          'a',
          { className: 'btn btn--style-primary', href: loginPath },
          label,
        ),
      )
    : createElement('p', null, 'Xignet sign-in is not enabled.');
}
