'use client';

import { createElement, useRef, useState } from 'react';
import { useConfig, useField } from '@payloadcms/ui';
import { directoryMessages } from './directory-messages.js';

/** Only public collection metadata crosses the client-component boundary. */
export function XignetDirectoryField({
  path,
  collection,
}: {
  path: string;
  collection: string;
}) {
  const { config } = useConfig();
  const email = useField<string>({ path: 'email' });
  const confirmation = useField<string>({ path });
  const issuer = useField<string>({ path: 'xignetIssuer' });
  const subject = useField<string>({ path: 'xignetSubject' });
  const [preview, setPreview] = useState<{ email: string; sub: string }>();
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const current =
    typeof email.value === 'string' ? email.value.trim().toLowerCase() : '';
  const currentEmail = useRef(current);
  currentEmail.current = current;
  async function lookup() {
    const requestedEmail = current;
    setBusy(true);
    setMessage('');
    setPreview(undefined);
    confirmation.setValue('');
    try {
      const response = await fetch(
        `${config.routes.api}/${encodeURIComponent(collection)}/xignet/resolve`,
        {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ email: requestedEmail }),
        },
      );
      if (!response.ok) {
        const error = (await response.json().catch(() => null)) as {
          error?: unknown;
        } | null;
        const code = error?.error;
        setMessage(
          typeof code === 'string' && Object.hasOwn(directoryMessages, code)
            ? directoryMessages[code as keyof typeof directoryMessages]
            : response.status === 403
              ? '沒有身分查詢權限。'
              : response.status === 400
                ? directoryMessages.invalid_email
                : directoryMessages.unavailable,
        );
        return;
      }
      const result = (await response.json()) as {
        identity: { issuer: string; email: string; sub: string };
        confirmation: string;
      };
      if (currentEmail.current !== requestedEmail) {
        setMessage('Email 已變更，請重新查詢 Xignet 身分。');
        return;
      }
      setPreview(result.identity);
      issuer.setValue(result.identity.issuer);
      subject.setValue(result.identity.sub);
      confirmation.setValue(result.confirmation);
    } catch {
      setMessage('身分查詢暫時無法使用，請稍後再試。');
    } finally {
      setBusy(false);
    }
  }
  return createElement(
    'div',
    { style: { marginBottom: '1.5rem' } },
    createElement(
      'button',
      {
        type: 'button',
        disabled: busy || !current,
        onClick: lookup,
        className: 'btn btn--style-secondary',
      },
      busy ? '查詢中…' : '查詢 Xignet 身分',
    ),
    preview && preview.email === current
      ? createElement(
          'p',
          { role: 'status' },
          `公司信箱：${preview.email}｜Xignet sub：${preview.sub}。請確認身分後儲存。`,
        )
      : createElement(
          'p',
          null,
          '新增用戶或變更 email 時，請先查詢並確認公司身分。',
        ),
    message ? createElement('p', { role: 'alert' }, message) : null,
  );
}
