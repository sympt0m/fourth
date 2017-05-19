#include "stdafx.h"

static volatile char *HELP = "Windows XP sucks and so does Visual C++ 2010, but I'm not about to shell out $200 for Windows 10 Pro for this keygenme stuff. I hate licensing costs.";

struct RSAKey {
	uint32_t d;
	uint32_t n;
	uint32_t e;
};

static void
randombytes(void *buf, size_t len)
{
	HCRYPTPROV p;

	if (!CryptAcquireContext(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		abort();

	if (!CryptGenRandom(p, (DWORD)len, buf))
		abort();

	CryptReleaseContext(p, 0);
}

static uint32_t
modexp(uint32_t b, uint32_t e, uint32_t m)
{
	uint32_t ret;
	uint64_t i;

	for (ret = 1; e != 0; e >>= 1) {
		if ((e & 1) == 1) {
			i = ret;
			i *= b;
			i %= m;
			ret = (uint32_t)i;
		}
		
		i = b;
		i *= b;
		i %= m;
		b = (uint32_t)i;
	}

	return ret;
}

#if GENERATING

/* lol RSA-32 */
static uint32_t
sign(const struct RSAKey *key, uint32_t seed)
{
	return modexp(seed, key->d, key->n);
}

static void
generateSerial(const struct RSAKey *key, uint32_t serial[])
{
	randombytes(&serial[0], sizeof(serial[0]));
	serial[1] = sign(key, serial[0]);
}

static void
encodeKey(char *key, const uint32_t serial[])
{
	static const char *alphabet = "ABCDEFGHIJKLMNOP";
	const uint8_t *serialb = (const uint8_t *)serial;
	size_t i;

	for (i = 0; i < 2 * sizeof(*serial); ++i) {
		*key++ = alphabet[serialb[i] >> 4];
		*key++ = alphabet[serialb[i] & 0xF];

		if (i != 0 && i != 2 * sizeof(*serial) - 1 && i % 2 == 1)
			*key++ = '-';
	}

	key[19] = '\0';
}

#else

static bool
verify(const struct RSAKey *key, uint32_t seed, uint32_t sig)
{
	/* Note: Normally verification functions operate over more than just one value.
	 *
	 * The correct way to verify is always timing-safe. In this case, we only
	 * compare one value, so the timing-safety is a given.
	 */
	return modexp(sig, key->e, key->n) == seed;
}

static int
decodeKey(uint32_t serial[], char *key)
{
	uint8_t *serialb = (uint8_t *)serial;

	serial[0] = 0;
	serial[1] = 0;

	while (*key != '\0') {
		if (*key == '-') {
			++key;
			continue;
		}
		if (*key < 'A' || *key > 'P')
			return -1;

		*serialb++ = ((key[0] - 'A') << 4) | (key[1] - 'A');
		key += 2;
	}

	return 0;
}

bool
isValidKey(const struct RSAKey *rsa, char *key)
{
	uint32_t serial[2];
	uint32_t *seed = serial, *sig = serial + 1;

	if (strlen(key) != 19 || key[4] != '-' || key[9] != '-' || key[14] != '-')
		return false;

	if (decodeKey(serial, key) != 0)
		return false;

	return verify(rsa, *seed, *sig);
}

#endif

int
main(int argc, char *argv[])
{
	const struct RSAKey rsa = {
#if GENERATING
		0x77e18239,
#else
		0,
#endif
		0xc0c9eb8d, 0x10001
	};

#if !(GENERATING)
	if (argc < 2) {
		fprintf(stderr, "Usage: %s key\n"
		"This program will print \"PASS\" if the key is valid.\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (isValidKey(&rsa, argv[1])) {
		puts("PASS");
		return EXIT_SUCCESS;
	} else {
		return EXIT_FAILURE;
	}
#else
	uint32_t serial[2];
	uint32_t *seed = serial, *checksum = serial + 1;
	/* LDJL-JDGP-BMBC-OODL */
	char key[20];

	generateSerial(&rsa, serial);
	encodeKey(key, serial);

	printf("%s (== 0x%08x / 0x%08x)\n", key, serial[0], serial[1]);

	return EXIT_SUCCESS;
#endif
}
