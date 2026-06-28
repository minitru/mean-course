const { timezoneLanguages } = require('./deviceIconUtils');

const CALLING_CODES = [
    ['972', 'IL', 'Israel'],
    ['971', 'AE', 'United Arab Emirates'],
    ['353', 'IE', 'Ireland'],
    ['351', 'PT', 'Portugal'],
    ['91', 'IN', 'India'],
    ['86', 'CN', 'China'],
    ['81', 'JP', 'Japan'],
    ['61', 'AU', 'Australia'],
    ['55', 'BR', 'Brazil'],
    ['52', 'MX', 'Mexico'],
    ['49', 'DE', 'Germany'],
    ['44', 'GB', 'United Kingdom'],
    ['39', 'IT', 'Italy'],
    ['34', 'ES', 'Spain'],
    ['33', 'FR', 'France'],
    ['1', 'US', 'United States']
];

const COUNTRY_ALIASES = {
    us: ['us', 'usa', 'united states', 'united states of america'],
    ca: ['ca', 'canada'],
    gb: ['gb', 'uk', 'united kingdom', 'great britain'],
    de: ['de', 'germany'],
    fr: ['fr', 'france'],
    es: ['es', 'spain'],
    it: ['it', 'italy'],
    mx: ['mx', 'mexico'],
    br: ['br', 'brazil'],
    au: ['au', 'australia'],
    jp: ['jp', 'japan'],
    cn: ['cn', 'china'],
    in: ['in', 'india'],
    ie: ['ie', 'ireland'],
    pt: ['pt', 'portugal'],
    il: ['il', 'israel'],
    ae: ['ae', 'united arab emirates', 'uae']
};

function normalizeCountryToken(value) {
    if (!value || typeof value !== 'string') {
        return null;
    }
    const token = value.trim().toLowerCase();
    if (!token || token === 'unknown' || token === 'local') {
        return null;
    }
    for (const [code, aliases] of Object.entries(COUNTRY_ALIASES)) {
        if (aliases.includes(token) || token === code) {
            return code;
        }
    }
    return token.length === 2 ? token : token;
}

function countriesMatch(a, b) {
    const left = normalizeCountryToken(a);
    const right = normalizeCountryToken(b);
    if (!left || !right) {
        return null;
    }
    return left === right;
}

function inferPhoneCallingCode(mobile) {
    if (!mobile || typeof mobile !== 'string') {
        return null;
    }
    const trimmed = mobile.trim();
    const digits = trimmed.replace(/\D/g, '');
    if (!digits) {
        return null;
    }

    if (trimmed.startsWith('+') || digits.length > 10) {
        for (const [code] of CALLING_CODES) {
            if (digits.startsWith(code)) {
                return code;
            }
        }
    }

    if (digits.length === 10 || (digits.length === 11 && digits.startsWith('1'))) {
        return '1';
    }

    return null;
}

function callingCodeToCountry(code) {
    const match = CALLING_CODES.find(([value]) => value === code);
    return match ? match[2] : null;
}

function analyzeLocaleSignals(browserInfo, referenceTimezone) {
    const browserTimezone = browserInfo?.timezone || null;
    const browserLanguages = Array.isArray(browserInfo?.languages) ? browserInfo.languages : [];
    const signals = [];

    if (browserTimezone && referenceTimezone && browserTimezone !== referenceTimezone) {
        signals.push({
            code: 'timezone-mismatch',
            severity: 'high',
            message: `Browser timezone ${browserTimezone} does not match network/GPS timezone ${referenceTimezone}`
        });
    }

    const expectedLangs = referenceTimezone ? timezoneLanguages[referenceTimezone] : null;
    if (expectedLangs?.length && browserLanguages.length) {
        const browserLangs = browserLanguages.map((lang) => String(lang).toLowerCase());
        const match = browserLangs.some((lang) =>
            expectedLangs.some((expected) => lang.startsWith(expected.toLowerCase()))
        );
        if (!match) {
            signals.push({
                code: 'language-timezone-mismatch',
                severity: 'medium',
                message: `Browser language ${browserLanguages[0]} is unusual for timezone ${referenceTimezone} (expected ${expectedLangs[0]})`
            });
        }
    }

    return signals;
}

function addSignal(signals, signal) {
    if (!signal) {
        return;
    }
    if (!signals.some((entry) => entry.code === signal.code && entry.message === signal.message)) {
        signals.push(signal);
    }
}

async function buildDerivedSignals(session, options = {}) {
    const signals = [];
    const mobile = options.mobile || session?.mobile || null;
    const phoneCallingCode = inferPhoneCallingCode(mobile);
    const phoneCountry = phoneCallingCode ? callingCodeToCountry(phoneCallingCode) : null;
    const ipCountry = session?.ipapi?.location?.country || session?.iplocation?.country || null;
    const ipCountryCode = session?.ipapi?.location?.country_code || null;
    const gpsCountry = session?.mapboxLocation?.country || null;
    const referenceTimezone = session?.ipapi?.location?.timezone
        || session?.iplocation?.timezone
        || null;

    if (phoneCallingCode && session?.ipapi?.location?.calling_code) {
        const ipCallingCode = String(session.ipapi.location.calling_code).replace(/\D/g, '');
        if (ipCallingCode && phoneCallingCode !== ipCallingCode) {
            addSignal(signals, {
                code: 'phone-ip-calling-code-mismatch',
                severity: 'high',
                message: `Phone calling code +${phoneCallingCode} does not match network calling code +${ipCallingCode}`
            });
        }
    }

    if (phoneCountry && ipCountry) {
        const match = countriesMatch(phoneCountry, ipCountry) || (ipCountryCode && countriesMatch(phoneCountry, ipCountryCode));
        if (match === false) {
            addSignal(signals, {
                code: 'phone-ip-country-mismatch',
                severity: 'high',
                message: `Phone country (${phoneCountry}) does not match network country (${ipCountry})`
            });
        }
    }

    if (phoneCountry && gpsCountry) {
        const match = countriesMatch(phoneCountry, gpsCountry);
        if (match === false) {
            addSignal(signals, {
                code: 'phone-gps-country-mismatch',
                severity: 'high',
                message: `Phone country (${phoneCountry}) does not match GPS country (${gpsCountry})`
            });
        }
    }

    for (const localeSignal of analyzeLocaleSignals(session?.browserInfo, referenceTimezone)) {
        addSignal(signals, localeSignal);
    }

    const sessionIp = session?.ipaddr || session?.ipapi?.ip || null;
    const mobileStats = session?.webrtcStats?.mobile;
    const reflexIp = mobileStats?.localRelatedAddress || mobileStats?.localIp || null;
    if (sessionIp && reflexIp && sessionIp !== reflexIp) {
        // Skip private/local IPs — WebRTC always exposes them, they're not a threat
        const priv = reflexIp.trim();
        const isPrivate = priv.startsWith('10.') || priv.startsWith('192.168.') ||
            priv.startsWith('172.16.') || priv.startsWith('172.17.') || priv.startsWith('172.18.') ||
            priv.startsWith('172.19.') || priv.startsWith('172.20.') || priv.startsWith('172.21.') ||
            priv.startsWith('172.22.') || priv.startsWith('172.23.') || priv.startsWith('172.24.') ||
            priv.startsWith('172.25.') || priv.startsWith('172.26.') || priv.startsWith('172.27.') ||
            priv.startsWith('172.28.') || priv.startsWith('172.29.') || priv.startsWith('172.30.') ||
            priv.startsWith('172.31.') || priv.startsWith('127.') || priv.startsWith('0.');
        if (!isPrivate) {
            addSignal(signals, {
                code: 'webrtc-reflex-ip-mismatch',
                severity: 'medium',
                message: `WebRTC reflexive IP ${reflexIp} differs from session IP ${sessionIp}`
            });
        }
    }

    for (const allocation of session?.turnStats?.allocations || []) {
        if (allocation.clientIp && sessionIp && allocation.clientIp !== sessionIp) {
        // Skip private/local IPs — TURN often relays through private networks
        const priv = allocation.clientIp.trim();
        const isPrivate = priv.startsWith('10.') || priv.startsWith('192.168.') ||
            priv.startsWith('172.16.') || priv.startsWith('172.17.') || priv.startsWith('172.18.') ||
            priv.startsWith('172.19.') || priv.startsWith('172.20.') || priv.startsWith('172.21.') ||
            priv.startsWith('172.22.') || priv.startsWith('172.23.') || priv.startsWith('172.24.') ||
            priv.startsWith('172.25.') || priv.startsWith('172.26.') || priv.startsWith('172.27.') ||
            priv.startsWith('172.28.') || priv.startsWith('172.29.') || priv.startsWith('172.30.') ||
            priv.startsWith('172.31.') || priv.startsWith('127.') || priv.startsWith('0.');
        if (!isPrivate) {
            addSignal(signals, {
                code: 'turn-client-ip-mismatch',
                severity: 'medium',
                message: `TURN client IP ${allocation.clientIp} differs from session IP ${sessionIp}`
            });
        }
        }
    }

    const networkRtt = session?.networkInfo?.rtt;
    const webrtcRtt = mobileStats?.rttMs ?? session?.webrtcStats?.operator?.rttMs ?? null;
    if (Number.isFinite(networkRtt) && Number.isFinite(webrtcRtt) && Math.abs(webrtcRtt - networkRtt) >= 150) {
        addSignal(signals, {
            code: 'webrtc-rtt-divergence',
            severity: 'medium',
            message: `WebRTC RTT ${webrtcRtt}ms diverges from network RTT ${networkRtt}ms`
        });
    }

    // Device fingerprint consistency
    if (session?.deviceFingerprint && session?.candidateId) {
        try {
            const mongoose = require('mongoose');
            const PreReg = require('../models/Enrollment');
            const Candidate = require('../models/Candidate');
            const candidate = await Candidate.findById(session.candidateId).select('email').lean();
            if (candidate?.email) {
                const preReg = await PreReg.findOne({
                    email: candidate.email.toLowerCase(),
                    baselineSubmittedAt: { $ne: null },
                    deviceFingerprint: { $ne: null }
                }).sort({ baselineSubmittedAt: -1 }).select('deviceFingerprint deviceInfo').lean();
                if (preReg) {
                    if (preReg.deviceFingerprint === session.deviceFingerprint) {
                        addSignal(signals, {
                            code: 'device-fingerprint-match',
                            severity: 'info',
                            message: 'Same device as enrollment baseline'
                        });
                    } else {
                        // ThumbmarkJS fingerprints can drift between visits on the same device.
                        // If the user agent string matches, it's almost certainly fingerprint drift, not a new device.
                        const uaMatch = preReg.deviceInfo && session.deviceInfo &&
                            preReg.deviceInfo === session.deviceInfo;
                        addSignal(signals, {
                            code: 'device-fingerprint-mismatch',
                            severity: uaMatch ? 'info' : 'medium',
                            message: uaMatch
                                ? 'Device fingerprint differs from enrollment baseline, but user agent matches — likely fingerprint drift'
                                : 'Device fingerprint differs from enrollment baseline — possible new device'
                        });
                    }
                } else {
                    addSignal(signals, {
                        code: 'device-fingerprint-captured',
                        severity: 'info',
                        message: 'Device fingerprint captured — no enrollment baseline to compare'
                    });
                }
            }
        } catch (e) { /* ignore */ }
    }

    return {
        phoneCallingCode,
        phoneCountry,
        ipCountry,
        gpsCountry,
        referenceTimezone,
        browserTimezone: session?.browserInfo?.timezone || null,
        browserLanguages: session?.browserInfo?.languages || [],
        signals
    };
}

module.exports = {
    buildDerivedSignals,
    analyzeLocaleSignals,
    inferPhoneCallingCode,
    normalizeCountryToken
};
