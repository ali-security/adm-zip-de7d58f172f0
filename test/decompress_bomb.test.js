"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../adm-zip");
const Utils = require("../util");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid unless `crcValue` is given) payload.
function craftBomb(declaredSize, method, content, crcValue) {
    const name = Buffer.from("a");
    // deliberately wrong by default: alloc used to happen before the crc check
    const crc = crcValue === undefined ? 0 : crcValue;
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    // RSS alone can miss the bug: a zero-filled multi-gigabyte Buffer.alloc is
    // committed lazily by the OS. Intercept Buffer.alloc instead and refuse any
    // request above LIMIT, so the declared-size allocation is caught on every
    // platform and Node version without actually committing gigabytes.
    describe("buffer allocations are bound by the real data, not the declared size", () => {
        const LIMIT = 64 * 1024 * 1024;
        const originalAlloc = Buffer.alloc;
        let largest;

        beforeEach(() => {
            largest = 0;
            Buffer.alloc = function (size) {
                if (size > largest) largest = size;
                if (size > LIMIT) throw new RangeError("unexpected allocation of " + size + " bytes");
                return originalAlloc.apply(Buffer, arguments);
            };
        });

        afterEach(() => {
            Buffer.alloc = originalAlloc;
        });

        const content = Buffer.from("A");
        const storedBomb = () => craftBomb(DECLARED, 0 /* STORED */, content, Utils.crc32(content));
        const deflatedBomb = () => craftBomb(DECLARED, 8 /* DEFLATED */, zlib.deflateRawSync(content), Utils.crc32(content));

        it("getData() on a STORED entry with invalid crc", () => {
            const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, content));
            expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
            expect(largest).to.be.below(LIMIT);
        });

        it("readFile() on a STORED entry", () => {
            const zip = new Zip(storedBomb());
            expect(zip.readFile("a").equals(content)).to.equal(true);
            expect(largest).to.be.below(LIMIT);
        });

        it("readFile() on a DEFLATED entry", () => {
            const zip = new Zip(deflatedBomb());
            expect(zip.readFile("a").equals(content)).to.equal(true);
            expect(largest).to.be.below(LIMIT);
        });

        it("readFileAsync() on a STORED entry", (done) => {
            const zip = new Zip(storedBomb());
            zip.readFileAsync("a", (data, err) => {
                try {
                    expect(err).to.equal(undefined);
                    expect(data.equals(content)).to.equal(true);
                    expect(largest).to.be.below(LIMIT);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });

        it("readFileAsync() on a DEFLATED entry", (done) => {
            const zip = new Zip(deflatedBomb());
            zip.readFileAsync("a", (data, err) => {
                try {
                    expect(err).to.equal(undefined);
                    expect(data.equals(content)).to.equal(true);
                    expect(largest).to.be.below(LIMIT);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});
