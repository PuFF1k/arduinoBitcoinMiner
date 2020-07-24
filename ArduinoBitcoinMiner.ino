#define uchar unsigned char
#define uint unsigned int
#define DBL_INT_ADD(a, b, c) \
 if (a > 0xffffffff - (c)) \
 ++b; \
 a += c;
#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))
typedef struct {
 uchar data[64];
 uint datalen;
 uint bitlen[2];
 long uint state[8];
} SHA256_CTX;
char fin[80];
int nonce = 0;
bool start = false;
bool reciveData[7] = { true, true, true, true, true, true, true };
char vers[9];
char prevbl[33];
char prevbl1[33];
char merkTr[33];
char merkTr1[33];
char bitsR[9];
char timeR[9];
char* test = "Serial.begin is Ready";
String ver;
String mrkl_root = "";
String prev_block = "";
//ver = Serial.read();
//unsigned long time_ = cmdMessenger.readInt32Arg();
//unsigned long bits = cmdMessenger.readInt32Arg();
//String prev_block = "000000000000000117c80378b8da0e33559b5997f2ad55e2f7d18ec1975b9717";
//String mrkl_root = "871714dcbae6c8193a2bb9b2a69fe1c0440399f38d94b3a0f1b447275a29978a";
//unsigned long time_ = 0x53058b35; // 2014 - 02 - 20 04:57 : 25
//unsigned long bits = 0x19015f53;
String time_;
String bits;
//------------------------my field------------------------------
void toBytes(unsigned long value, char* arr)
{
 arr[0] = value & 0xFF; // 0x78
 arr[1] = (value >> 8) & 0xFF; // 0x56
 arr[2] = (value >> 16) & 0xFF; // 0x34
 arr[3] = (value >> 24) & 0xFF; // 0x12
}
void clearBuffer()
{
 unsigned long now = millis();
 while (millis() - now < 500)
 Serial.read();
}
long uint k[64] = {
 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
0x923f82a4, 0xab1c5ed5,
 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
0x9bdc06a7, 0xc19bf174,
 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
0x5cb0a9dc, 0x76f988da,
 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
0x06ca6351, 0x14292967,
 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb,
0x81c2c92e, 0x92722c85,
 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
0xf40e3585, 0x106aa070,
 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
0x5b9cca4f, 0x682e6ff3,
 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb,
0xbef9a3f7, 0xc67178f2
};
void SHA256Transform(SHA256_CTX* ctx, unsigned char* data)
{
 long uint a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
 long uint dataTransformed[64];
 for (int kl = 0; kl < 64; kl++) {
 dataTransformed[kl] = data[kl];
 }
 for (i = 0, j = 0; i < 16; ++i, j += 4) {
 m[i] = (dataTransformed[j] << 24) | ((dataTransformed[j + 1] << 8) <<
8) | (dataTransformed[j + 2] << 8) | (dataTransformed[j + 3]);
 }
 for (; i < 64; ++i) {
 m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
 }
 a = ctx->state[0];
 b = ctx->state[1];
 c = ctx->state[2];
 d = ctx->state[3];
 e = ctx->state[4];
 f = ctx->state[5];
 g = ctx->state[6];
 h = ctx->state[7];
 for (i = 0; i < 64; ++i) {
 t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
 t2 = EP0(a) + MAJ(a, b, c);
 h = g;
 g = f;
 f = e;
 e = d + t1;
 d = c;
 c = b;
 b = a;
 a = t1 + t2;
 }
 ctx->state[0] += a;
 ctx->state[1] += b;
 ctx->state[2] += c;
 ctx->state[3] += d;
 ctx->state[4] += e;
 ctx->state[5] += f;
 ctx->state[6] += g;
 ctx->state[7] += h;
}
void SHA256Init(SHA256_CTX* ctx)
{
 ctx->datalen = 0;
 ctx->bitlen[0] = 0;
 ctx->bitlen[1] = 0;
 ctx->state[0] = 0x6a09e667;
 ctx->state[1] = 0xbb67ae85;
 ctx->state[2] = 0x3c6ef372;
 ctx->state[3] = 0xa54ff53a;
 ctx->state[4] = 0x510e527f;
 ctx->state[5] = 0x9b05688c;
 ctx->state[6] = 0x1f83d9ab;
 ctx->state[7] = 0x5be0cd19;
}
void SHA256Update(SHA256_CTX* ctx, uchar data[], uint len)
{
 for (uint i = 0; i < len; ++i) {
 ctx->data[ctx->datalen] = data[i];
 ctx->datalen++;
 if (ctx->datalen == 64) {
 SHA256Transform(ctx, ctx->data);
 DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], 512);
 ctx->datalen = 0;
 }
 }
}
void SHA256Final(SHA256_CTX* ctx, uchar hash[])
{
 uint i = ctx->datalen;
 if (ctx->datalen < 56) {
 ctx->data[i++] = 0x80;
 while (i < 56)
 ctx->data[i++] = 0x00;
 }
 else {
 ctx->data[i++] = 0x80;
 while (i < 64)
 ctx->data[i++] = 0x00;
 SHA256Transform(ctx, ctx->data);
 memset(ctx->data, 0, 56);
 }
 DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen * 8);
 ctx->data[63] = ctx->bitlen[0];
 ctx->data[62] = ctx->bitlen[0] >> 8;
 ctx->data[61] = ctx->bitlen[0] >> 16;
 ctx->data[60] = ctx->bitlen[0] >> 24;
 ctx->data[59] = ctx->bitlen[1];
 ctx->data[58] = ctx->bitlen[1] >> 8;
 ctx->data[57] = ctx->bitlen[1] >> 16;
 ctx->data[56] = ctx->bitlen[1] >> 24;
 SHA256Transform(ctx, ctx->data);
 for (i = 0; i < 4; ++i) {
 hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
 hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
 hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
 hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
 hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
 hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
 hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
 hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
 }
}
String SHA256(char* data, int strLen, char* output)
{
 //int strLen = strlen(data);
 SHA256_CTX ctx;
 unsigned char hash[32];
 String hashStr = "";
 SHA256Init(&ctx);
 SHA256Update(&ctx, (unsigned char*)data, strLen);
 SHA256Final(&ctx, hash);
 char s[3];
 for (int i = 0; i < 32; i++) {
 output[i] = hash[i];
 sprintf(s, "%02x", hash[i]);
 hashStr += s;
 }
 return hashStr;
}
void reciveDataNow()
{
 if (Serial.available() == 8 && reciveData[0] == true) {
 Serial.readBytesUntil('\r', vers, sizeof(vers) - 1);
 vers[8] = '\0';
 Serial.print("recived1 : ");
 Serial.println(vers);
 clearBuffer();
 reciveData[0] = false;
 }
 if (Serial.available() == 32 && reciveData[1] == true && reciveData[0] ==
false) {
 Serial.readBytesUntil('\r', prevbl, sizeof(prevbl) - 1);
 prevbl[32] = '\0';
 Serial.print("recived2 : ");
 Serial.println(prevbl);
 //clearBuffer();
 reciveData[1] = false;
 }
 if (Serial.available() == 32 && reciveData[2] == true && reciveData[1] ==
false) {
 Serial.readBytesUntil('\r', prevbl1, sizeof(prevbl1) - 1);
 prevbl1[32] = '\0';
 Serial.print("recived3 : ");
 Serial.println(prevbl1);
 clearBuffer();
 reciveData[2] = false;
 }
 if (Serial.available() == 32 && reciveData[3] == true && reciveData[2] ==
false) {
 Serial.readBytesUntil('\r', merkTr, sizeof(merkTr) - 1);
 merkTr[32] = '\0';
 Serial.print("recived4 : ");
 Serial.println(merkTr);
 //clearBuffer();
 reciveData[3] = false;
 }
 if (Serial.available() == 32 && reciveData[4] == true && reciveData[3] ==
false) {
 Serial.readBytesUntil('\r', merkTr1, sizeof(merkTr1) - 1);
 merkTr1[32] = '\0';
 Serial.print("recived5 : ");
 Serial.println(merkTr1);
 clearBuffer();
 reciveData[4] = false;
 }
 if (Serial.available() == 8 && reciveData[5] == true && reciveData[4] ==
false) {
 Serial.readBytesUntil('\r', timeR, sizeof(timeR) - 1);
 timeR[8] = '\0';
 Serial.print("recived6 : ");
 Serial.println(timeR);
 clearBuffer();
 reciveData[5] = false;
 }
 if (Serial.available() == 8 && reciveData[6] == true && reciveData[5] ==
false) {
 Serial.readBytesUntil('\r', bitsR, sizeof(bitsR) - 1);
 bitsR[8] = '\0';
 Serial.print("recived7 : ");
 Serial.println(bitsR);
 clearBuffer();
 reciveData[6] = false;
 start = true;
 }
 if (start == true) {
 ver = vers;
 time_ = timeR;
 bits = bitsR;
 String prev_block0 = prevbl;
 String prev_block1 = prevbl1;
 String mrkl_root0 = merkTr;
 String mrkl_root1 = merkTr1;
 prev_block = prev_block0 + prev_block1;
 mrkl_root = mrkl_root0 + mrkl_root1;
 String byteString = "";
 char z[32];
 for (unsigned int i = 0; i < prev_block.length(); i += 2) {
 byteString = "";
 byteString = prev_block.substring(i, i + 2);
 char copy = (char)strtol(byteString.c_str(), NULL, 16);
 z[31 - i / 2] = copy;
 }
 char y[32];
 for (unsigned int i = 0; i < mrkl_root.length(); i += 2) {
 String byteString = mrkl_root.substring(i, i + 2);
 char copy1 = strtol(byteString.c_str(), NULL, 16);
 y[31 - i / 2] = copy1;
 }
 //unsigned long _byteswap_ulong(unsigned long ver);
 unsigned long _byteswap_ulong(unsigned long time_);
 unsigned long _byteswap_ulong(unsigned long bits);
 unsigned long _byteswap_ulong(unsigned long nonce);
 char verBytes[4];
 for (unsigned int i = 0; i < ver.length(); i += 2) {
 String byteString = "";
 byteString = ver.substring(i, i + 2);
 char copy1 = strtol(byteString.c_str(), NULL, 16);
 verBytes[3 - i / 2] = copy1;
 }
 fin[0] = verBytes[0];
 fin[1] = verBytes[1];
 fin[2] = verBytes[2];
 fin[3] = verBytes[3];
 for (int m = 4; m <= 35; m++) {
 fin[m] = z[m - 4];
 //Serial.println( fin[m]);
 }
 for (int p = 36; p <= 67; p++) {
 fin[p] = y[p - 36];
 }
 char timeBytes[4];
 for (unsigned int i = 0; i < time_.length(); i += 2) {
 String byteString = "";
 byteString = time_.substring(i, i + 2);
 char copy1 = strtol(byteString.c_str(), NULL, 16);
 timeBytes[3 - i / 2] = copy1;
 }
 fin[68] = timeBytes[0];
 fin[69] = timeBytes[1];
 fin[70] = timeBytes[2];
 fin[71] = timeBytes[3];
 char bitsBytes[4];
 for (unsigned int i = 0; i < bits.length(); i += 2) {
 String byteString = "";
 byteString = bits.substring(i, i + 2);
 char copy1 = strtol(byteString.c_str(), NULL, 16);
 bitsBytes[3 - i / 2] = copy1;
 }
 fin[72] = bitsBytes[0];
 fin[73] = bitsBytes[1];
 fin[74] = bitsBytes[2];
 fin[75] = bitsBytes[3];
 }
}
void array_to_string(byte array[], unsigned int len, char buffer[])
{
 for (unsigned int i = 0; i < len; i++) {
 byte nib1 = (array[i] >> 4) & 0x0F;
 byte nib2 = (array[i] >> 0) & 0x0F;
 buffer[i * 2 + 0] = nib1 < 0xA ? '0' + nib1 : 'A' + nib1 - 0xA;
 buffer[i * 2 + 1] = nib2 < 0xA ? '0' + nib2 : 'A' + nib2 - 0xA;
 }
 buffer[len * 2] = '\0';
}
// ------------------ M A I N ----------------------
// Setup function
void setup()
{
 // Listen on serial connection for messages from the pc
 Serial.begin(9600);
}
// Loop function
void loop()
{
 if (reciveData[6] == true) {
 reciveDataNow();
 }
 if (start == true) {
 char nonceBytes[4];
 toBytes(nonce, nonceBytes);
 fin[76] = nonceBytes[0];
 fin[77] = nonceBytes[1];
 fin[78] = nonceBytes[2];
 fin[79] = nonceBytes[3];
 //char str[80] = "";
 //array_to_string(fin, 80, str);
 //Serial.println(str);
 char fin2[32];
 String fgh = SHA256(fin, 80, fin2);
 String zec = SHA256(fin2, 32, fin2);
 // Serial.print(nonce + 1);
 // Serial.print(" ");
 Serial.println(zec);
 reciveData[4] = false;
 nonce++;
 }
}
