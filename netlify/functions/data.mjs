// Fetches the newest file under the "Newsletter" prefix in the private
// DigitalOcean Space, using AWS Signature V4 auth. The access keys are read
// from Netlify environment variables (SPACES_KEY / SPACES_SECRET) — never
// commit them to this repo.
import { createHash, createHmac } from 'node:crypto';

const HOST = 'ntar-bucket.syd1.digitaloceanspaces.com';
const PREFIX = 'Newsletter';
const REGION = 'syd1';

export default async () => {
  if (!process.env.SPACES_KEY || !process.env.SPACES_SECRET) {
    return json(500, {
      error: 'SPACES_KEY and/or SPACES_SECRET are not set. Add them under ' +
             'Site configuration → Environment variables in Netlify, then redeploy.',
    });
  }

  // List everything under the Newsletter prefix. The query string must be in
  // sorted order, as it is signed.
  const listRes = await signedFetch('/', `list-type=2&prefix=${PREFIX}`);
  const listXml = await listRes.text();
  if (!listRes.ok) {
    return json(502, { error: `Bucket listing returned ${listRes.status}`, detail: listXml.slice(0, 500) });
  }

  // Pick the most recently modified real file (skip zero-byte folder markers).
  const objects = [...listXml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)]
    .map(m => ({
      key: m[1].match(/<Key>([\s\S]*?)<\/Key>/)?.[1],
      modified: m[1].match(/<LastModified>(.*?)<\/LastModified>/)?.[1] ?? '',
      size: Number(m[1].match(/<Size>(\d+)<\/Size>/)?.[1] ?? 0),
    }))
    .filter(o => o.key && !o.key.endsWith('/') && o.size > 0)
    .sort((a, b) => b.modified.localeCompare(a.modified));

  if (!objects.length) {
    return json(404, { error: `No files found under "${PREFIX}" in the bucket.` });
  }

  const newest = objects[0];
  const path = '/' + newest.key.split('/').map(encodeRfc3986).join('/');
  const fileRes = await signedFetch(path);
  const body = await fileRes.text();
  if (!fileRes.ok) {
    return json(502, { error: `Fetching "${newest.key}" returned ${fileRes.status}`, detail: body.slice(0, 500) });
  }

  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'x-newsletter-file': encodeURIComponent(newest.key),
      'x-newsletter-modified': newest.modified,
    },
  });
};

// Signed GET request to the Space (AWS Signature V4).
async function signedFetch(path, query = '') {
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const emptyHash = createHash('sha256').update('').digest('hex');

  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = [
    'GET',
    path,
    query,
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
  const kSigning = hmac(hmac(hmac(hmac('AWS4' + process.env.SPACES_SECRET, dateStamp), REGION), 's3'), 'aws4_request');
  const signature = createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  return fetch(`https://${HOST}${path}${query ? '?' + query : ''}`, {
    headers: {
      'x-amz-date': amzDate,
      'x-amz-content-sha256': emptyHash,
      authorization: `AWS4-HMAC-SHA256 Credential=${process.env.SPACES_KEY}/${scope}, ` +
                     `SignedHeaders=${signedHeaders}, Signature=${signature}`,
    },
  });
}

// S3 requires RFC 3986 encoding of each path segment in signed URLs.
const encodeRfc3986 = s => encodeURIComponent(s)
  .replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());

const json = (status, obj) => new Response(JSON.stringify(obj), {
  status,
  headers: { 'content-type': 'application/json' },
});

export const config = { path: '/data' };
