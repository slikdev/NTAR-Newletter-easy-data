// Fetches the Newsletter file from the private DigitalOcean Space using
// AWS Signature V4 auth. The access keys are read from Netlify environment
// variables (SPACES_KEY / SPACES_SECRET) — never commit them to this repo.
import { createHash, createHmac } from 'node:crypto';

const HOST = 'ntar-bucket.syd1.digitaloceanspaces.com';
const KEY_PATH = '/Newsletter';
const REGION = 'syd1';

export default async () => {
  const accessKey = process.env.SPACES_KEY;
  const secretKey = process.env.SPACES_SECRET;
  if (!accessKey || !secretKey) {
    return json(500, {
      error: 'SPACES_KEY and/or SPACES_SECRET are not set. Add them under ' +
             'Site configuration → Environment variables in Netlify, then redeploy.',
    });
  }

  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const emptyHash = createHash('sha256').update('').digest('hex');

  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = [
    'GET',
    KEY_PATH,
    '',
    `host:${HOST}\nx-amz-content-sha256:${emptyHash}\nx-amz-date:${amzDate}\n`,
    signedHeaders,
    emptyHash,
  ].join('\n');

  const scope = `${dateStamp}/${REGION}/s3/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    scope,
    createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');

  const hmac = (key, data) => createHmac('sha256', key).update(data).digest();
  const kSigning = hmac(hmac(hmac(hmac('AWS4' + secretKey, dateStamp), REGION), 's3'), 'aws4_request');
  const signature = createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  const res = await fetch(`https://${HOST}${KEY_PATH}`, {
    headers: {
      'x-amz-date': amzDate,
      'x-amz-content-sha256': emptyHash,
      authorization: `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope}, ` +
                     `SignedHeaders=${signedHeaders}, Signature=${signature}`,
    },
  });

  const body = await res.text();
  if (!res.ok) {
    return json(502, { error: `Bucket returned ${res.status}`, detail: body.slice(0, 500) });
  }
  return new Response(body, {
    status: 200,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
};

const json = (status, obj) => new Response(JSON.stringify(obj), {
  status,
  headers: { 'content-type': 'application/json' },
});

export const config = { path: '/data' };
