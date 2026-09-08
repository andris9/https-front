'use strict';

// The store an instance upgraded from 1.4.x or earlier still has in Redis. Its
// certificates and its ACME account are carried over on the first lookup that
// needs them, rather than being re-ordered from Let's Encrypt.

const test = require('node:test');
const assert = require('node:assert/strict');

const {
    ACCOUNT_KID,
    DAY,
    accountSettingKey,
    certs,
    closeDb,
    flushTestDb,
    issueCertificate,
    legacyAccountKey,
    legacyCertKey,
    redisClient,
    seedCertificate,
    seedLegacyAccount,
    seedLegacyCertificate,
    signedCert,
    signedKey,
    stubAcme,
    useLocalDomainChecks,
    waitFor
} = require('./helpers');
const { getCertificate } = require('../lib/certs');

// A self signed certificate for legacy.example.com, standing in for one an
// earlier release had ordered. Generated with:
// openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -subj "/CN=legacy.example.com" \
//   -addext "subjectAltName=DNS:legacy.example.com" -not_before 20250101000000Z -not_after 20350101000000Z
const LEGACY_CERT = `-----BEGIN CERTIFICATE-----
MIIDOjCCAiKgAwIBAgIULqCeUhmtgkkxseX5MRcFHanyh2QwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSbGVnYWN5LmV4YW1wbGUuY29tMB4XDTI1MDEwMTAwMDAw
MFoXDTM1MDEwMTAwMDAwMFowHTEbMBkGA1UEAwwSbGVnYWN5LmV4YW1wbGUuY29t
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyWk4SKqRaSj3o+cupN2B
JbY9xOK4kBesAsVdTmHYZJm1ayYrK0AwSJsNjAE/8O08liECYObvQZUy1qPvzR4S
0QdvQpzGOOansI/h1FmiSiK8mLQMc1FWE99kzrzN859dwLdut1Y+6zvWQrdqnwWs
RvL4/oozDzR9N8+OXbVRsPaYqNSMyQIXiiJzv5LRFRREecqHUo2DvS6Zestp/dYl
Pt7HSI/mlc97B9fVOxPtCVwCyvHfwyV7z4Jb28JIiWf/6p74ONjxSkBWmolRsR1G
2zRiY9V1OobEF0mBCzDhi91eCVKdDjGzObVN8H7ZjinyCfysoUbJ1Xcoul9XRgq6
SQIDAQABo3IwcDAdBgNVHQ4EFgQUE+F4wuenR4WwrRDMysfpQBaCItYwHwYDVR0j
BBgwFoAUE+F4wuenR4WwrRDMysfpQBaCItYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HREEFjAUghJsZWdhY3kuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBABlS
5BELinsb4wQAJUaJyUacv74D1tH4YmqDe/3mv3OelYpWvJAVsasaQpvadIfkCtzo
9SZOv4sKEhLr2cCNPGHHY+XSqxbvAHiLd7ReoXyscgkpqdej0hJV2/gDA+PNKN50
WePM+dT3diaJcLB5DrYa+9Wo65vuvRKm1xVkRPs9w8CL0YNYqeoxype75J4s2j1U
pY5NyQghMo514dvwtFSM7lsf6Q9CtyQrXAJie8b3/eZDgtQNRWxNZaxO/66YRGP9
rio2ACVzLy3r0SxUs8Bvf3xBbOuL7qtdfDenznifx0Imp5YaA2NHPd7K7rF+YPi5
EyO0gZa04t7SGfCVXnA=
-----END CERTIFICATE-----`;

// A self signed certificate that expired in 2024, so that the import has
// something to reject. Generated the same way, with
// -not_before 20240101000000Z -not_after 20240401000000Z
const EXPIRED_CERT = `-----BEGIN CERTIFICATE-----
MIIDPDCCAiSgAwIBAgITe0zw+ENEI4D8v7QWwL0j+oqbPzANBgkqhkiG9w0BAQsF
ADAeMRwwGgYDVQQDDBNleHBpcmVkLmV4YW1wbGUuY29tMB4XDTI0MDEwMTAwMDAw
MFoXDTI0MDQwMTAwMDAwMFowHjEcMBoGA1UEAwwTZXhwaXJlZC5leGFtcGxlLmNv
bTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8FHCxdlKjFwy8PmHsY
bUcAt7ZRQibn4OXbvfrKDnSAOMKpwBpLLykts8Z+AEToxaNnMRMSn4a3FL7Gc1J6
+ynfOFZ7Eu24juIwdX1MXCckO96B92sQu9AD2hk3nuE+uaIp/0ttqvw9dGqxqkZq
Ls+zGdxg2GoHxeN/iwTcyt43KMxq/Q9f/qy3mPjPs4TyETSbtCZ0nJkhuXktWV5v
8ztLQK0xtNbikBB1ZXh+fmm+COyMp+v7zHLNfSZCLJwjmwOj5blwsbS+kDM1oaIq
Rv6ayuMne1GjT09um7Bm+Uqrr3/0+GeevzPY61f8YtEScgf6K6hP5rpxPb5w6hgq
U58CAwEAAaNzMHEwHQYDVR0OBBYEFOlSloLAgu22cQs09BKCHuS8ISfOMB8GA1Ud
IwQYMBaAFOlSloLAgu22cQs09BKCHuS8ISfOMA8GA1UdEwEB/wQFMAMBAf8wHgYD
VR0RBBcwFYITZXhwaXJlZC5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEA
CEDY4k8ICNFHUUsLanzEmAOqVOylLWS4JermS4oGJx2MkJbfhmtfHWC4aEH0UHSl
HKYVWS/sOHL8AMno6FNKopW/0Def63JpVIXsELx5/z2GGpG1nRvWkC38R9fTSVAb
CRzkY875JB7dfiB6ByJjDNt8FzHDwwsXm/lER6ryUv7GIxEqT1F+E6D7Zcl5Uh78
p+oE41z2tNCtPMbVj/nFVjjwSOT6x60MvZSACZT/NSK0WV4v96A57thHQuaARfnv
zIg48mI5uYPG/7wouh1B+WtNqxEqZW9yhbbbKl3an4CamNRUUYXKca/0hp6pmpCj
c7SQ1JHFjrw3Yz373IQAGg==
-----END CERTIFICATE-----`;

let restoreDomainChecks;

test.before(async () => {
    await flushTestDb();
});

test.after(async () => {
    await closeDb();
});

test.beforeEach(async () => {
    await flushTestDb();
    restoreDomainChecks = useLocalDomainChecks();
});

test.afterEach(() => restoreDomainChecks());

test('a certificate stored by an earlier release is served instead of ordering a new one', async t => {
    const { createCertificate, resolveCaa } = stubAcme(t);

    await seedLegacyCertificate('legacy.example.com', { cert: LEGACY_CERT, key: signedKey, expires: Date.now() + 60 * DAY });

    const cert = await getCertificate('legacy.example.com');

    assert.equal(cert.cert, LEGACY_CERT);
    assert.equal(cert.privateKey, signedKey);
    assert.deepEqual(cert.ca, ['legacy-chain']);
    assert.equal(cert.status, 'valid');
    // the names and the dates come from the certificate itself rather than from
    // the old record
    assert.deepEqual(cert.altNames, ['legacy.example.com']);
    assert.equal(createCertificate.mock.callCount(), 0, 'nothing was ordered');
    assert.equal(resolveCaa.mock.callCount(), 0, 'and the domain was not revalidated to serve what is already held');

    assert.deepEqual(await certs().listCertificateDomains(), ['legacy.example.com']);

    // the old entry is left alone, and the next lookup no longer needs it
    assert.equal(await redisClient.exists(legacyCertKey('legacy.example.com')), 1);
    await redisClient.del(legacyCertKey('legacy.example.com'));
    assert.equal((await getCertificate('legacy.example.com')).cert, LEGACY_CERT);
});

test('a certificate that does not cover the domain is not imported', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    // the certificate names legacy.example.com, the entry is filed under another
    // domain, so importing it would serve the wrong certificate for that name
    await seedLegacyCertificate('mismatch.example.com', { cert: LEGACY_CERT, key: signedKey, expires: Date.now() + 60 * DAY });

    const cert = await getCertificate('mismatch.example.com');

    assert.equal(createCertificate.mock.callCount(), 1, 'a certificate was ordered instead');
    assert.equal(cert.cert, signedCert);
});

test('a certificate the store has already ordered is not reverted to the old one', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    // an entry an earlier release left behind, for a domain that has since been
    // ordered under the new store
    await seedLegacyCertificate('reordered.example.com', { cert: LEGACY_CERT, key: signedKey, expires: Date.now() + 60 * DAY });
    await seedCertificate('reordered.example.com', { expires: Date.now() + 20 * DAY, cert: signedCert });

    // due for renewal, so the renewal path runs and the old entry is in reach
    const cert = await getCertificate('reordered.example.com');
    assert.equal(cert.cert, signedCert, 'the certificate in place is served');

    await waitFor(() => createCertificate.mock.callCount() > 0);

    const stored = await certs().getCertificate('reordered.example.com', true);
    assert.equal(stored.cert, signedCert, 'the renewal replaced it, not the old entry');
    assert.notEqual(stored.privateKey, signedKey);
});

test('an expired certificate of an earlier release is not imported', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    await seedLegacyCertificate('expired.example.com', { cert: EXPIRED_CERT, key: signedKey, expires: Date.now() - DAY });

    const cert = await getCertificate('expired.example.com');

    // there was nothing worth keeping, so a certificate was ordered instead
    assert.equal(createCertificate.mock.callCount(), 1);
    assert.equal(cert.cert, signedCert);
    assert.notEqual(cert.privateKey, signedKey, 'the order generated a key of its own');
});

test('an unreadable entry of an earlier release is ignored', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    await seedLegacyCertificate('broken.example.com', { cert: 'not a certificate', key: signedKey, expires: Date.now() + 60 * DAY });
    // an entry with a private key but no certificate is what a failed order left
    // behind, and there is nothing in it to import either
    await redisClient.hdel(legacyCertKey('keyonly.example.com'), 'cert');
    await redisClient.hset(legacyCertKey('keyonly.example.com'), 'key', signedKey);

    assert.equal((await getCertificate('broken.example.com')).cert, signedCert);
    assert.equal((await getCertificate('keyonly.example.com')).cert, signedCert);
    assert.equal(createCertificate.mock.callCount(), 2, 'both domains were ordered from scratch');
});

test('the ACME account of an earlier release is reused', async t => {
    const { createAccount, createCertificate } = stubAcme(t, { order: issueCertificate });

    await seedLegacyAccount(signedKey, ACCOUNT_KID);

    await getCertificate('account-import.example.com');

    assert.equal(createAccount.mock.callCount(), 0, 'no new account was registered');
    assert.equal(createCertificate.mock.calls[0].arguments[0].accountKey, signedKey);
    assert.equal(createCertificate.mock.calls[0].arguments[0].kid, ACCOUNT_KID);

    const stored = await certs().settings.get(accountSettingKey(certs()));
    assert.equal(stored.privateKey, signedKey);
    assert.equal(stored.account.key.kid, ACCOUNT_KID);

    // the old entry is left alone
    assert.equal(await redisClient.hexists(legacyAccountKey(), 'key'), 1);
});

test('an account entry of an earlier release that can not be read is replaced', async t => {
    const { createAccount } = stubAcme(t, { order: issueCertificate });

    await redisClient.hmset(legacyAccountKey(), { key: signedKey, account: 'not json' });

    await getCertificate('account-broken.example.com');

    assert.equal(createAccount.mock.callCount(), 1, 'a new account was registered instead');
});

test('an account entry of an earlier release without an account URL keeps its key', async t => {
    const { createAccount, createCertificate } = stubAcme(t, { order: issueCertificate });

    // an older release stored the key without the account URL
    await seedLegacyAccount(signedKey);

    await getCertificate('account-no-kid.example.com');

    // the key is registered again rather than replaced, which the CA answers with
    // the registration it already has for it
    assert.equal(createAccount.mock.callCount(), 1);
    assert.equal(createAccount.mock.calls[0].arguments[0].key, signedKey);
    assert.equal(createCertificate.mock.calls[0].arguments[0].accountKey, signedKey);
});
