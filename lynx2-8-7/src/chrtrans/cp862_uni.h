/*
 * Compile-in this chunk of code unless we've turned it off specifically
 * or in general (id=_cp862).
 */

#ifndef INCL_CHARSET_cp862
#define INCL_CHARSET_cp862 1

/*ifdef NO_CHARSET*/
#ifdef  NO_CHARSET
#undef  NO_CHARSET
#endif
#define NO_CHARSET 0 /* force default to always be active */

/*ifndef NO_CHARSET_cp862*/
#ifndef NO_CHARSET_cp862

#if    ALL_CHARSETS
#define NO_CHARSET_cp862 0
#else
#define NO_CHARSET_cp862 1
#endif

#endif /* ndef(NO_CHARSET_cp862) */

#if NO_CHARSET_cp862
#define UC_CHARSET_SETUP_cp862 /*nothing*/
#else

/*
 *  uni_hash.tbl
 *
 *  Do not edit this file; it was automatically generated by
 *
 *  ./makeuctb ./cp862_uni.tbl
 *
 */

static const u8 dfont_unicount_cp862[256] = 
{
	  0,   0,   0,   0,   0,   0,   0,   0,
	  0,   0,   0,   0,   0,   0,   0,   0,
	  0,   0,   0,   0,   0,   0,   0,   0,
	  0,   0,   0,   0,   0,   0,   0,   0,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1
};

static const u16 dfont_unitable_cp862[224] = 
{
	0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
	0x0028, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x002f,
	0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
	0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f,
	0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
	0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f,
	0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
	0x0058, 0x0059, 0x005a, 0x005b, 0x005c, 0x005d, 0x005e, 0x005f,
	0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
	0x0068, 0x0069, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f,
	0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
	0x0078, 0x0079, 0x007a, 0x007b, 0x007c, 0x007d, 0x007e, 0x007f,
	0x05d0, 0x05d1, 0x05d2, 0x05d3, 0x05d4, 0x05d5, 0x05d6, 0x05d7,
	0x05d8, 0x05d9, 0x05da, 0x05db, 0x05dc, 0x05dd, 0x05de, 0x05df,
	0x05e0, 0x05e1, 0x05e2, 0x05e3, 0x05e4, 0x05e5, 0x05e6, 0x05e7,
	0x05e8, 0x05e9, 0x05ea, 0x00a2, 0x00a3, 0x00a5, 0x20a7, 0x0192,
	0x00e1, 0x00ed, 0x00f3, 0x00fa, 0x00f1, 0x00d1, 0x00aa, 0x00ba,
	0x00bf, 0x2310, 0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb,
	0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
	0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510,
	0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f,
	0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567,
	0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b,
	0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580,
	0x03b1, 0x00df, 0x0393, 0x03c0, 0x03a3, 0x03c3, 0x00b5, 0x03c4,
	0x03a6, 0x0398, 0x03a9, 0x03b4, 0x221e, 0x03c6, 0x03b5, 0x2229,
	0x2261, 0x00b1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00f7, 0x2248,
	0x00b0, 0x2219, 0x00b7, 0x221a, 0x207f, 0x00b2, 0x25a0, 0x00a0
};

/* static struct unipair_str repl_map_cp862[]; */

static const struct unimapdesc_str dfont_replacedesc_cp862 = {0,NULL,0,1};
#define UC_CHARSET_SETUP_cp862 UC_Charset_Setup("cp862",\
"Hebrew (cp862)",\
dfont_unicount_cp862,dfont_unitable_cp862,224,\
dfont_replacedesc_cp862,128,1,862)

#endif /* NO_CHARSET_cp862 */

#endif /* INCL_CHARSET_cp862 */
