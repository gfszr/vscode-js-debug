"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.shaHashFile = exports.hashFile = exports.shaHash = exports.hash = void 0;
const chromehash_1 = require("./pkg/chromehash");
const fs_1 = require("fs");
const string_decoder_1 = require("string_decoder");
const crypto_1 = require("crypto");
const output = Buffer.alloc(4 * 5);
/** Runs a traditional pre-Chrome 104 hash of the bytes. */
const hash = (input) => {
    const hash = new chromehash_1.Hasher();
    hash.update(normalizeChromehashBuffer(input));
    hash.digest(output);
    hash.free();
    return output.toString('hex');
};
exports.hash = hash;
/** Runs a traditional pre-Chrome 104 hash of the bytes. */
const shaHash = (input) => {
    const hash = (0, crypto_1.createHash)('sha256');
    hash.update(normalizeShaBuffer(input));
    return hash.digest('hex');
};
exports.shaHash = shaHash;
/** Runs a traditional pre-Chrome 104 hash of the file. */
const hashFile = async (file, bufferSize = 4096) => {
    if (bufferSize % 2 === 1) {
        bufferSize++; // ensure buffer size is even for the swap16() in BE BOM reading.
    }
    const buf = Buffer.alloc(bufferSize);
    const hasher = new chromehash_1.Hasher();
    let fd;
    try {
        fd = await fs_1.promises.open(file, 'r');
        let lastRead = await fd.read(buf, 0, buf.length, null);
        const bomBuf = buf.slice(0, lastRead.bytesRead);
        if (hasUtf16LEBOM(bomBuf)) {
            hasher.update(bomBuf.slice(2)); // add the trailing BOM read byte
            while (lastRead.bytesRead === buf.length) {
                lastRead = await fd.read(buf, 0, buf.length, null);
                hasher.update(buf.slice(0, lastRead.bytesRead));
            }
        }
        else if (hasUtf16BEBOM(bomBuf)) {
            hasher.update(bomBuf.slice(2).swap16()); // add the trailing BOM read byte
            while (lastRead.bytesRead === buf.length) {
                lastRead = await fd.read(buf, 0, buf.length, null);
                hasher.update(buf.slice(0, lastRead.bytesRead).swap16());
            }
        }
        else if (hasUTF8BOM(bomBuf)) {
            const decoder = new string_decoder_1.StringDecoder('utf8');
            hasher.update(Buffer.from(decoder.write(bomBuf.slice(3)), 'utf16le'));
            while (lastRead.bytesRead === buf.length) {
                lastRead = await fd.read(buf, 0, buf.length, null);
                hasher.update(Buffer.from(decoder.write(buf.slice(0, lastRead.bytesRead)), 'utf16le'));
            }
        }
        else {
            const decoder = new string_decoder_1.StringDecoder('utf8');
            hasher.update(Buffer.from(decoder.write(bomBuf), 'utf16le'));
            while (lastRead.bytesRead === buf.length) {
                lastRead = await fd.read(buf, 0, buf.length, null);
                hasher.update(Buffer.from(decoder.write(buf.slice(0, lastRead.bytesRead)), 'utf16le'));
            }
        }
        hasher.digest(output);
        return output.toString('hex');
    }
    finally {
        hasher.free();
        if (fd !== undefined) {
            await fd.close();
        }
    }
};
exports.hashFile = hashFile;
const decodeOpts = { stream: true };
/** Runs a modern SHA hash of the file */
const shaHashFile = async (file, bufferSize = 4096) => {
    if (bufferSize % 2 === 1) {
        bufferSize++; // ensure buffer size is even for the swap16() in BE BOM reading.
    }
    const buf = Buffer.alloc(bufferSize);
    const hasher = (0, crypto_1.createHash)('sha256');
    let fd;
    try {
        fd = await fs_1.promises.open(file, 'r');
        let lastRead = await fd.read(buf, 0, buf.length, null);
        const bomBuf = buf.slice(0, lastRead.bytesRead);
        if (hasUtf16LEBOM(bomBuf)) {
            const decoder = new TextDecoder('utf-16le');
            hasher.update(decoder.decode(bomBuf.slice(2), decodeOpts)); // add the trailing BOM read byte
            while (lastRead.bytesRead > 0) {
                lastRead = await fd.read(buf, 0, buf.length, null);
                hasher.update(decoder.decode(buf.slice(0, lastRead.bytesRead), decodeOpts));
            }
        }
        else if (hasUtf16BEBOM(bomBuf)) {
            const decoder = new TextDecoder('utf-16be');
            hasher.update(decoder.decode(bomBuf.slice(2), decodeOpts)); // add the trailing BOM read byte
            while (lastRead.bytesRead > 0) {
                lastRead = await fd.read(buf, 0, buf.length, null);
                hasher.update(decoder.decode(buf.slice(0, lastRead.bytesRead), decodeOpts));
            }
        }
        else if (hasUTF8BOM(bomBuf)) {
            hasher.update(bomBuf.slice(3));
            while (lastRead.bytesRead > 0) {
                lastRead = await fd.read(buf, 0, buf.length, null);
                hasher.update(buf.slice(0, lastRead.bytesRead));
            }
        }
        else {
            hasher.update(bomBuf);
            while (lastRead.bytesRead > 0) {
                lastRead = await fd.read(buf, 0, buf.length, null);
                hasher.update(buf.slice(0, lastRead.bytesRead));
            }
        }
        return hasher.digest('hex');
    }
    finally {
        await (fd === null || fd === void 0 ? void 0 : fd.close());
    }
};
exports.shaHashFile = shaHashFile;
const hasUTF8BOM = (buffer) => buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf;
const hasUtf16LEBOM = (buffer) => buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe;
const hasUtf16BEBOM = (buffer) => buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff;
const normalizeChromehashBuffer = (buffer) => {
    if (hasUTF8BOM(buffer)) {
        return utf8ToUtf16(buffer.slice(3));
    }
    if (hasUtf16LEBOM(buffer)) {
        return buffer.slice(2);
    }
    if (hasUtf16BEBOM(buffer)) {
        return buffer.slice(2).swap16();
    }
    return utf8ToUtf16(buffer);
};
const normalizeShaBuffer = (buffer) => {
    if (hasUTF8BOM(buffer)) {
        return buffer.slice(3);
    }
    if (hasUtf16LEBOM(buffer)) {
        return new TextEncoder().encode(new TextDecoder('utf-16le').decode(buffer.slice(2)));
    }
    if (hasUtf16BEBOM(buffer)) {
        return new TextEncoder().encode(new TextDecoder('utf-16be').decode(buffer.slice(2)));
    }
    return buffer;
};
const utf8ToUtf16 = (buffer) => Buffer.from(buffer.toString('utf8'), 'utf16le');
