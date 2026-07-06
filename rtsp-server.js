"use strict";

/**
 * Minimal RTSP 1.0 server (RFC 2326) with RTP-over-TCP interleaving (no external
 * dependency, no ffmpeg). It exposes each existing H.264 "track" produced by
 * UBoxLiveStreamManager (see ubox-live-stream.js) as an RTSP mount point, e.g.:
 *
 *   rtsp://<host>:8554/live/primary
 *   rtsp://<host>:8554/live/secondary
 *
 * Design choices (documented on purpose, see README section added alongside):
 *  - Video-only (H.264). No audio track is produced by ubox-web today.
 *  - RTP is always carried "interleaved" inside the RTSP TCP connection
 *    (RTP/AVP/TCP), never over separate UDP ports. This keeps the
 *    implementation small and firewall/NAT-friendly, at the cost of not
 *    honoring UDP transport requests. Force your client to TCP if it
 *    doesn't already default to it (e.g. `ffplay -rtsp_transport tcp ...`).
 *  - No RTCP sender reports are generated; playback works fine without them
 *    for a video-only, no-seek live feed, but multi-stream A/V sync (if audio
 *    is added later) would need it.
 *  - Optional HTTP Basic auth (RTSP_USER / RTSP_PASS) since RTSP has no
 *    session concept shared with the existing web login.
 */

/**
 * Minimal RTSP 1.0 server (RFC 2326) with RTP-over-TCP interleaving (no external
 * dependency, no ffmpeg). It exposes each existing video "track" produced by
 * UBoxLiveStreamManager (see ubox-live-stream.js) as an RTSP mount point, e.g.:
 *
 *   rtsp://<host>:8554/live/primary
 *   rtsp://<host>:8554/live/secondary
 *
 * Supports both H.264 (RFC 6184) and H.265/HEVC (RFC 7798) transparently,
 * auto-detected per track the same way ubox-live-stream.js already does
 * (video-codec.js's detectStreamFormat), since some UBox cameras stream HEVC.
 *
 * Design choices (documented on purpose, see README section added alongside):
 *  - Video-only. No audio track is produced by ubox-web today.
 *  - RTP is always carried "interleaved" inside the RTSP TCP connection
 *    (RTP/AVP/TCP), never over separate UDP ports. This keeps the
 *    implementation small and firewall/NAT-friendly, at the cost of not
 *    honoring UDP transport requests. Force your client to TCP if it
 *    doesn't already default to it (e.g. `ffplay -rtsp_transport tcp ...`).
 *  - No RTCP sender reports are generated; playback works fine without them
 *    for a video-only, no-seek live feed.
 *  - Optional HTTP Basic auth (RTSP_USER / RTSP_PASS) since RTSP has no
 *    session concept shared with the existing web login.
 */

const net = require("net");
const crypto = require("crypto");

const RTP_PAYLOAD_TYPE = 96; // dynamic payload type, used for both H.264 and HEVC
const RTP_MAX_PAYLOAD = 1400; // conservative, keeps interleaved frames well under typical MTU
const H264_FU_A_TYPE = 28;
const HEVC_FU_NAL_TYPE = 49;

function randomUInt(bytes) {
  return crypto.randomBytes(bytes).readUIntBE(0, bytes);
}

// --- Annex-B parsing (self-contained: computes both H.264 and HEVC NAL type
// interpretations for each unit, since the codec isn't known up front). ---

function findStartCodes(buffer) {
  const starts = [];
  for (let i = 0; i < buffer.length - 2; i += 1) {
    if (buffer[i] !== 0 || buffer[i + 1] !== 0) continue;
    if (buffer[i + 2] === 1) {
      starts.push({ offset: i, length: 3 });
      i += 2;
    } else if (buffer[i + 2] === 0 && buffer[i + 3] === 1) {
      starts.push({ offset: i, length: 4 });
      i += 3;
    }
  }
  return starts;
}

function parseAnnexBNalUnits(buffer) {
  const starts = findStartCodes(buffer);
  const units = [];
  for (let i = 0; i < starts.length; i += 1) {
    const start = starts[i].offset + starts[i].length;
    let end = i + 1 < starts.length ? starts[i + 1].offset : buffer.length;
    while (end > start && buffer[end - 1] === 0) end -= 1;
    if (end <= start) continue;
    const data = buffer.subarray(start, end);
    units.push({
      data,
      h264Type: data[0] & 0x1f,
      hevcType: (data[0] >> 1) & 0x3f,
    });
  }
  return units;
}

// Mirrors video-codec.js's detectStreamFormat() so a track is classified the
// same way the existing WebCodecs player already classifies it.
function detectFormat(nalUnits) {
  if (nalUnits.some((n) => n.h264Type === 7 || n.h264Type === 8 || n.h264Type === 5)) return "h264";
  if (nalUnits.some((n) => [32, 33, 34, 19, 20, 21].includes(n.hevcType))) return "hevc";
  return null;
}

// --- RTP packet assembly, shared tail (header + sequence/timestamp/ssrc). ---

function finalizeRtpPackets(track, payloads, timestamp) {
  return payloads.map((data, index) => {
    const marker = index === payloads.length - 1;
    const header = Buffer.alloc(12);
    header[0] = 0x80; // version 2, no padding, no extension, no CSRC
    header[1] = (marker ? 0x80 : 0) | (RTP_PAYLOAD_TYPE & 0x7f);
    header.writeUInt16BE(track.seq & 0xffff, 2);
    track.seq = (track.seq + 1) & 0xffff;
    header.writeUInt32BE(timestamp >>> 0, 4);
    header.writeUInt32BE(track.ssrc >>> 0, 8);
    return Buffer.concat([header, data]);
  });
}

// RFC 6184: 1-byte NAL header, FU-A fragmentation.
function buildH264RtpPackets(track, nalUnits, timestamp) {
  const payloads = [];
  nalUnits.forEach((nal) => {
    const nalHeader = nal.data[0];
    const nri = nalHeader & 0x60;
    const nalType = nalHeader & 0x1f;

    if (nal.data.length <= RTP_MAX_PAYLOAD) {
      payloads.push(Buffer.from(nal.data));
      return;
    }
    const payload = nal.data.subarray(1);
    let offset = 0;
    let first = true;
    while (offset < payload.length) {
      const chunkSize = Math.min(RTP_MAX_PAYLOAD - 2, payload.length - offset);
      const isLast = offset + chunkSize >= payload.length;
      const fuIndicator = nri | H264_FU_A_TYPE;
      let fuHeader = nalType;
      if (first) fuHeader |= 0x80;
      if (isLast) fuHeader |= 0x40;
      payloads.push(Buffer.concat([Buffer.from([fuIndicator, fuHeader]), payload.subarray(offset, offset + chunkSize)]));
      offset += chunkSize;
      first = false;
    }
  });
  return finalizeRtpPackets(track, payloads, timestamp);
}

// RFC 7798: 2-byte NAL header, FU (type 49) fragmentation.
function buildHevcRtpPackets(track, nalUnits, timestamp) {
  const payloads = [];
  nalUnits.forEach((nal) => {
    const data = nal.data;
    if (data.length <= RTP_MAX_PAYLOAD) {
      payloads.push(Buffer.from(data));
      return;
    }
    const byte0 = data[0];
    const byte1 = data[1];
    const originalType = (byte0 >> 1) & 0x3f;
    const fuByte0 = (byte0 & 0x81) | (HEVC_FU_NAL_TYPE << 1); // keep F bit + layer-id-high, replace type with 49
    const fuByte1 = byte1; // layer-id-low + TID unchanged
    const payload = data.subarray(2);
    let offset = 0;
    let first = true;
    while (offset < payload.length) {
      const chunkSize = Math.min(RTP_MAX_PAYLOAD - 3, payload.length - offset);
      const isLast = offset + chunkSize >= payload.length;
      let fuHeader = originalType & 0x3f;
      if (first) fuHeader |= 0x80;
      if (isLast) fuHeader |= 0x40;
      payloads.push(Buffer.concat([Buffer.from([fuByte0, fuByte1, fuHeader]), payload.subarray(offset, offset + chunkSize)]));
      offset += chunkSize;
      first = false;
    }
  });
  return finalizeRtpPackets(track, payloads, timestamp);
}

function parseTransportInterleaved(transportHeader = "") {
  const match = /interleaved=(\d+)-(\d+)/.exec(transportHeader);
  if (!match) return null;
  return { rtp: Number(match[1]), rtcp: Number(match[2]) };
}

function tryReadNextFrame(buffer) {
  if (!buffer.length) return null;

  if (buffer[0] === 0x24 /* '$' */) {
    if (buffer.length < 4) return null;
    const len = buffer.readUInt16BE(2);
    if (buffer.length < 4 + len) return null;
    return { kind: "interleaved-in", rest: buffer.subarray(4 + len) };
  }

  const headerEnd = buffer.indexOf("\r\n\r\n");
  if (headerEnd === -1) return null;

  const headerText = buffer.subarray(0, headerEnd).toString("utf8");
  const lines = headerText.split("\r\n");
  const [method, url, version] = (lines[0] || "").split(" ");
  const headers = {};
  for (let i = 1; i < lines.length; i += 1) {
    const idx = lines[i].indexOf(":");
    if (idx === -1) continue;
    headers[lines[i].slice(0, idx).trim().toLowerCase()] = lines[i].slice(idx + 1).trim();
  }

  const contentLength = Number(headers["content-length"] || 0);
  const bodyStart = headerEnd + 4;
  if (buffer.length < bodyStart + contentLength) return null;

  const body = buffer.subarray(bodyStart, bodyStart + contentLength).toString("utf8");
  const rest = buffer.subarray(bodyStart + contentLength);
  return { kind: "request", req: { method, url, version, headers, body }, rest };
}

class RtspTrack {
  constructor(name) {
    this.name = name;
    this.format = null; // "h264" | "hevc", detected from the first frames
    this.vps = null; // HEVC only
    this.sps = null;
    this.pps = null;
    this.ssrc = randomUInt(4);
    this.seq = randomUInt(2);
    this.tsBase = randomUInt(4);
    this.startedAtMs = null;
    this.sessions = new Set();
  }
}

class RtspServer {
  constructor({ port = 8554, basePath = "/live", auth = null } = {}) {
    this.port = port;
    this.basePath = `/${basePath.replace(/^\/+|\/+$/g, "")}`;
    this.auth = auth; // { user, pass } | null
    this.tracks = new Map();
    this.server = net.createServer((socket) => this.handleConnection(socket));
  }

  listen() {
    this.server.listen(this.port, () => {
      console.log(`RTSP server listening on rtsp://0.0.0.0:${this.port}${this.basePath}/<track> (TCP interleaved only)`);
    });
    this.server.on("error", (error) => console.error(`RTSP server error: ${error.message}`));
  }

  close() {
    for (const track of this.tracks.values()) {
      for (const session of track.sessions) {
        try { session.socket.end(); } catch { /* ignore */ }
      }
    }
    this.server.close();
  }

  ensureTrack(name) {
    if (!this.tracks.has(name)) this.tracks.set(name, new RtspTrack(name));
    return this.tracks.get(name);
  }

  // Called by UBoxLiveStreamManager for every decoded Annex-B access unit.
  pushFrame(trackName, annexB) {
    const track = this.ensureTrack(trackName);
    const nals = parseAnnexBNalUnits(annexB);
    if (!nals.length) return;

    if (!track.format) {
      const detected = detectFormat(nals);
      if (detected) track.format = detected;
    }

    if (track.format === "hevc") {
      for (const nal of nals) {
        if (nal.hevcType === 32) track.vps = Buffer.from(nal.data);
        else if (nal.hevcType === 33) track.sps = Buffer.from(nal.data);
        else if (nal.hevcType === 34) track.pps = Buffer.from(nal.data);
      }
    } else if (track.format === "h264") {
      for (const nal of nals) {
        if (nal.h264Type === 7) track.sps = Buffer.from(nal.data);
        else if (nal.h264Type === 8) track.pps = Buffer.from(nal.data);
      }
    }

    if (!track.sessions.size) return; // nobody watching over RTSP right now

    if (track.startedAtMs === null) track.startedAtMs = Date.now();
    const elapsedMs = Date.now() - track.startedAtMs;
    const timestamp = track.tsBase + Math.round(elapsedMs * 90); // 90kHz clock

    const packets = track.format === "hevc"
      ? buildHevcRtpPackets(track, nals, timestamp)
      : buildH264RtpPackets(track, nals, timestamp);
    for (const session of track.sessions) this.sendInterleaved(session, packets);
  }

  sendInterleaved(session, packets) {
    for (const packet of packets) {
      const frame = Buffer.alloc(4 + packet.length);
      frame[0] = 0x24;
      frame[1] = session.interleaved.rtp;
      frame.writeUInt16BE(packet.length, 2);
      packet.copy(frame, 4);
      try {
        session.socket.write(frame);
      } catch {
        if (session.track) session.track.sessions.delete(session);
      }
    }
  }

  resolveTrackName(url) {
    let pathname;
    try {
      pathname = new URL(url).pathname;
    } catch {
      pathname = url.startsWith("/") ? url : `/${url}`;
    }
    if (!pathname.startsWith(`${this.basePath}/`)) return null;
    const rest = pathname.slice(this.basePath.length + 1);
    const name = rest.split("/")[0];
    return name || null;
  }

  checkAuth(headers) {
    if (!this.auth) return true;
    const header = headers.authorization || "";
    if (!header.startsWith("Basic ")) return false;
    const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
    const idx = decoded.indexOf(":");
    if (idx === -1) return false;
    const user = decoded.slice(0, idx);
    const pass = decoded.slice(idx + 1);
    return user === this.auth.user && pass === this.auth.pass;
  }

  paramsReady(track) {
    if (track.format === "hevc") return Boolean(track.vps && track.sps && track.pps);
    if (track.format === "h264") return Boolean(track.sps && track.pps);
    return false;
  }

  waitForParams(track, timeoutMs) {
    if (this.paramsReady(track)) return Promise.resolve(true);
    return new Promise((resolve) => {
      const start = Date.now();
      const timer = setInterval(() => {
        if (this.paramsReady(track)) {
          clearInterval(timer);
          resolve(true);
        } else if (Date.now() - start > timeoutMs) {
          clearInterval(timer);
          resolve(false);
        }
      }, 100);
    });
  }

  buildSdp(track) {
    if (track.format === "hevc") {
      const vpsB64 = track.vps.toString("base64");
      const spsB64 = track.sps.toString("base64");
      const ppsB64 = track.pps.toString("base64");
      return [
        "v=0",
        `o=- ${Date.now()} 1 IN IP4 0.0.0.0`,
        "s=UBox Live",
        "c=IN IP4 0.0.0.0",
        "t=0 0",
        "a=control:*",
        "m=video 0 RTP/AVP 96",
        "a=rtpmap:96 H265/90000",
        `a=fmtp:96 sprop-vps=${vpsB64};sprop-sps=${spsB64};sprop-pps=${ppsB64}`,
        "a=control:trackID=1",
        "",
      ].join("\r\n");
    }

    const spsB64 = track.sps.toString("base64");
    const ppsB64 = track.pps.toString("base64");
    const profileLevelId = track.sps.subarray(1, 4).toString("hex");
    return [
      "v=0",
      `o=- ${Date.now()} 1 IN IP4 0.0.0.0`,
      "s=UBox Live",
      "c=IN IP4 0.0.0.0",
      "t=0 0",
      "a=control:*",
      "m=video 0 RTP/AVP 96",
      "a=rtpmap:96 H264/90000",
      `a=fmtp:96 packetization-mode=1;profile-level-id=${profileLevelId};sprop-parameter-sets=${spsB64},${ppsB64}`,
      "a=control:trackID=1",
      "",
    ].join("\r\n");
  }

  reply(socket, code, statusText, cseq, extraHeaders = {}, body = null) {
    const headers = { CSeq: cseq || "0", ...extraHeaders };
    if (body) {
      headers["Content-Type"] = headers["Content-Type"] || "application/sdp";
      headers["Content-Length"] = Buffer.byteLength(body);
    }
    const headerLines = Object.entries(headers)
      .map(([key, value]) => `${key}: ${value}`)
      .join("\r\n");
    const response = `RTSP/1.0 ${code} ${statusText}\r\n${headerLines}\r\n\r\n${body || ""}`;
    try {
      socket.write(response);
    } catch {
      /* socket already gone */
    }
  }

  async handleRequest(session, req) {
    const cseq = req.headers.cseq;

    if (req.method !== "OPTIONS" && !this.checkAuth(req.headers)) {
      return this.reply(session.socket, 401, "Unauthorized", cseq, {
        "WWW-Authenticate": 'Basic realm="ubox-web-rtsp"',
      });
    }

    switch (req.method) {
      case "OPTIONS":
        return this.reply(session.socket, 200, "OK", cseq, {
          Public: "OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER",
        });

      case "DESCRIBE": {
        const trackName = this.resolveTrackName(req.url);
        if (!trackName) return this.reply(session.socket, 404, "Not Found", cseq);
        const track = this.ensureTrack(trackName);
        const ready = await this.waitForParams(track, 4000);
        if (!ready) return this.reply(session.socket, 503, "Service Unavailable", cseq);
        const contentBase = req.url.endsWith("/") ? req.url : `${req.url}/`;
        return this.reply(session.socket, 200, "OK", cseq, { "Content-Base": contentBase }, this.buildSdp(track));
      }

      case "SETUP": {
        const trackName = this.resolveTrackName(req.url);
        if (!trackName) return this.reply(session.socket, 404, "Not Found", cseq);
        session.track = this.ensureTrack(trackName);
        session.state = "READY";
        session.interleaved = parseTransportInterleaved(req.headers.transport) || { rtp: 0, rtcp: 1 };
        return this.reply(session.socket, 200, "OK", cseq, {
          Transport: `RTP/AVP/TCP;unicast;interleaved=${session.interleaved.rtp}-${session.interleaved.rtcp}`,
          Session: `${session.id};timeout=60`,
        });
      }

      case "PLAY": {
        if (!session.track) return this.reply(session.socket, 455, "Method Not Valid In This State", cseq);
        session.state = "PLAYING";
        session.track.sessions.add(session);
        return this.reply(session.socket, 200, "OK", cseq, {
          Session: `${session.id};timeout=60`,
          Range: "npt=0.000-",
        });
      }

      case "PAUSE": {
        if (session.track) session.track.sessions.delete(session);
        session.state = "READY";
        return this.reply(session.socket, 200, "OK", cseq, { Session: `${session.id};timeout=60` });
      }

      case "TEARDOWN": {
        if (session.track) session.track.sessions.delete(session);
        session.state = "INIT";
        this.reply(session.socket, 200, "OK", cseq, { Session: `${session.id};timeout=60` });
        return session.socket.end();
      }

      case "GET_PARAMETER":
      case "SET_PARAMETER":
        return this.reply(session.socket, 200, "OK", cseq, { Session: `${session.id};timeout=60` });

      default:
        return this.reply(session.socket, 501, "Not Implemented", cseq);
    }
  }

  handleConnection(socket) {
    socket.setNoDelay(true);
    const session = {
      id: crypto.randomBytes(6).toString("hex"),
      socket,
      state: "INIT",
      track: null,
      interleaved: { rtp: 0, rtcp: 1 },
    };

    let buffer = Buffer.alloc(0);
    const cleanup = () => {
      if (session.track) session.track.sessions.delete(session);
    };

    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      let parsed;
      // eslint-disable-next-line no-cond-assign
      while ((parsed = tryReadNextFrame(buffer))) {
        buffer = parsed.rest;
        if (parsed.kind === "request") {
          this.handleRequest(session, parsed.req).catch((error) => {
            console.error(`RTSP request error: ${error.message}`);
            this.reply(socket, 500, "Internal Server Error", parsed.req.headers.cseq);
          });
        }
      }
    });

    socket.on("error", cleanup);
    socket.on("close", cleanup);
  }
}

module.exports = { RtspServer };
