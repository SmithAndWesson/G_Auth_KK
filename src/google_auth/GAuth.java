package google_auth;

import java.util.Date;

public class GAuth {
    private String key;
    private int[] strToHash;
    private int strBinLen;

    public String generate(String secret) {
//        long epoch = 0;
        key = base32tohex(secret);
        if (key.length() % 2 != 0) {
            key += "0";
        }
//        if (0 == epoch) {
//            epoch = Math.round((new Date()).getTime() / 1e3);
//        }
//        String time = leftpad(dec2hex(Math.floor(epoch / 30)), 16, "0");

        String time = getHexTime();
        this.strBinLen = time.length() * 4;
        this.strToHash = hex2binb(time);

        String hmac = getHMAC();
        int offset = 0;
        offset = (int)hex2dec(hmac.substring(hmac.length() - 1));
        String otp = (hex2dec(hmac.substring(2 * offset, 2 * offset + 8)) & hex2dec("7fffffff")) + "";
        return otp.substring(otp.length() - 6, otp.length());
    }

    public String getHexTime() {
        long epoch = Math.round((new Date()).getTime() / 1e3);
        return leftpad(dec2hex(Math.floor(epoch / 30)), 16, "0");
    }

    public double getTime() {
        return Math.floor(Math.round((new Date()).getTime() / 1e3));
    }

    public String getHMAC() {
        int blockByteSize, blockBitSize, i, lastArrayIndex, hashBitSize;
        int[] keyWithIPad = new int[32];
        int[] keyWithOPad = new int[32];
        int[] keyToUse = new int[16];
        long[] retVal = new long[5];

        blockByteSize = 64;
        hashBitSize = 160;

        keyToUse = hex2binb(key);

        blockBitSize = blockByteSize * 8;
        lastArrayIndex = (blockByteSize / 4) - 1;

        keyToUse[lastArrayIndex] &= 0xFFFFFF00;

        for (i = 0; i <= lastArrayIndex; i += 1) {
            keyWithIPad[i] = keyToUse[i] ^ 0x36363636;
            keyWithOPad[i] = keyToUse[i] ^ 0x5C5C5C5C;
        }

        keyWithIPad[16] = this.strToHash[0];
        keyWithIPad[17] = this.strToHash[1];
        retVal = coreSHA1(keyWithIPad, blockBitSize + this.strBinLen);

        keyWithOPad[16] = (int)retVal[0];
        keyWithOPad[17] = (int)retVal[1];
        keyWithOPad[18] = (int)retVal[2];
        keyWithOPad[19] = (int)retVal[3];
        keyWithOPad[20] = (int)retVal[4];
        retVal = coreSHA1(keyWithOPad, blockBitSize + hashBitSize);

        return binb2hex(retVal);
    }

    public long[] coreSHA1(int[] f, int g) {
        long[] W = new long[80];
        long a, b, c, d, e, T;
        int appendedMessageLength;
        long[] H = {0x67452301L, 0xefcdab89L, 0x98badcfeL, 0x10325476L, 0xc3d2e1f0L};
        long[] K = {0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x5a827999L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x6ed9eba1L, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0x8f1bbcdcL, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L, 0xca62c1d6L};

        f[g >> 5] |= 0x80 << (24 - (g % 32));
        f[(((g + 65) >> 9) << 4) + 15] = g;
        appendedMessageLength = f.length;
        for (int i = 0; i < appendedMessageLength; i += 16) {
            a = H[0];
            b = H[1];
            c = H[2];
            d = H[3];
            e = H[4];
            for (int t = 0; t < 80; t += 1) {
                if (t < 16) {
                    W[t] = f[t + i];
                } else {
                    W[t] = rotl_32(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
                }
                if (t < 20) {
                    T = safeAdd_32_5(rotl_32(a, 5), ch_32(b, c, d), e, K[t], W[t]);
                } else if (t < 40) {
                    T = safeAdd_32_5(rotl_32(a, 5), parity_32(b, c, d), e, K[t], W[t]);
                } else if (t < 60) {
                    T = safeAdd_32_5(rotl_32(a, 5), maj_32(b, c, d), e, K[t], W[t]);
                } else {
                    T = safeAdd_32_5(rotl_32(a, 5), parity_32(b, c, d), e, K[t], W[t]);
                }
                e = d;
                d = c;
                c = rotl_32(b, 30);
                b = a;
                a = T;
            }
            H[0] = safeAdd_32_2(a, H[0]);
            H[1] = safeAdd_32_2(b, H[1]);
            H[2] = safeAdd_32_2(c, H[2]);
            H[3] = safeAdd_32_2(d, H[3]);
            H[4] = safeAdd_32_2(e, H[4]);
        }
        return H;
    }

    public int rotl_32(long x, int n) {
        return (((int)x << n) | ((int)x >>> (32 - n)));
    }

    public long ch_32(long x, long y, long z) {
        return (x & y) ^ (~x & z);
    }

    public long parity_32(long x, long y, long z) {
        return x ^ y ^ z;
    }

    public long maj_32(long x, long y, long z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    public int safeAdd_32_2(long x, long y) {
        long a = (x & 0xFFFF) + (y & 0xFFFF)
                , msw = (x >>> 16) + (y >>> 16) + (a >>> 16);
        return (int)(((msw & 0xFFFF) << 16) | (a & 0xFFFF));
    }

    public int safeAdd_32_5(long a, long b, long c, long d, long e) {
        long f = (a & 0xFFFF) + (b & 0xFFFF) + (c & 0xFFFF) + (d & 0xFFFF) + (e & 0xFFFF)
                , msw = (a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) + (e >>> 16) + (f >>> 16);
        return (int)(((msw & 0xFFFF) << 16) | (f & 0xFFFF));
    }

    public String dec2hex(double s) {
        return (s < 15.5 ? "0" : "") + Integer.toString((int)Math.round(s), 16);
    }

    public long hex2dec(String a) {
        return Long.parseLong(a, 16);
    }

    public String base32tohex(String base32) {
        String base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", bits = "", hex = "";
        for (int i = 0; i < base32.length(); i++) {
            int val = base32chars.indexOf(base32.charAt(i));
            bits += leftpad(Integer.toString(val, 2), 5, "0");
        }
        for (int i = 0; i + 4 <= bits.length(); i += 4) {
            String chunk = bits.substring(i, i + 4);
            hex += Integer.toString(Integer.parseInt(chunk, 2), 16);
        }
        return hex;
    }

    public String leftpad(String str, int len, String pad) {
        str = ("0000000000000000" + str).substring(("0000000000000000" + str).length() - len);
        return str;
    }

    public int[] hex2binb(String a) {
        int[] b = new int[16];
        int length = a.length();
        int i;
        int num;
        for (i = 0; i < length; i += 2) {
            num = Integer.parseInt(a.substring(i, i + 2), 16);
            b[i >> 3] |= num << (24 - (4 * (i % 8)));
        }
        return b;
    }

    public String binb2hex(long[] a) {
        int hexCase = 0;
        String b = (hexCase != 0) ? "0123456789ABCDEF" : "0123456789abcdef";
        String str = "";
        int length = a.length * 4;
        int srcByte;
        for (int i = 0; i < length; i += 1) {
            srcByte = (int)a[i >> 2] >> ((3 - (i % 4)) * 8);
            str += String.valueOf(b.charAt((srcByte >> 4) & 0xF)) + String.valueOf(b.charAt(srcByte & 0xF));
        }
        return str;
    }
}