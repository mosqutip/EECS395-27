/*
 * Compile-in this chunk of code unless we've turned it off specifically
 * or in general (id=_iso_8859_6).
 */

#ifndef INCL_CHARSET_iso_8859_6
#define INCL_CHARSET_iso_8859_6 1

/*ifdef NO_CHARSET*/
#ifdef  NO_CHARSET
#undef  NO_CHARSET
#endif
#define NO_CHARSET 0 /* force default to always be active */

/*ifndef NO_CHARSET_iso_8859_6*/
#ifndef NO_CHARSET_iso_8859_6

#if    ALL_CHARSETS
#define NO_CHARSET_iso_8859_6 0
#else
#define NO_CHARSET_iso_8859_6 1
#endif

#endif /* ndef(NO_CHARSET_iso_8859_6) */

#if NO_CHARSET_iso_8859_6
#define UC_CHARSET_SETUP_iso_8859_6 /*nothing*/
#else

/*
 *  uni_hash.tbl
 *
 *  Do not edit this file; it was automatically generated by
 *
 *  ./makeuctb ./iso06_uni.tbl
 *
 */

static const u8 dfont_unicount_iso_8859_6[256] = 
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
	  1,   1,   1,   1,   1,   1,   1,   0,
	  0,   0,   0,   0,   0,   0,   0,   0,
	  0,   0,   0,   0,   0,   0,   0,   0,
	  0,   0,   0,   0,   0,   0,   0,   0,
	  0,   0,   0,   0,   0,   0,   0,   0,
	  1,   0,   0,   0,   1,   0,   0,   0,
	  0,   0,   0,   0,   1,   1,   0,   0,
	  0,   0,   0,   0,   0,   0,   0,   0,
	  0,   0,   0,   1,   0,   0,   0,   1,
	  0,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   0,   0,   0,   0,   0,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   0,   0,   0,   0,   0,
	  0,   0,   0,   0,   0,   0,   0,   0
};

static const u16 dfont_unitable_iso_8859_6[146] = 
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
	0x0078, 0x0079, 0x007a, 0x007b, 0x007c, 0x007d, 0x007e, 0x00a0,
	0x00a4, 0x060c, 0x00ad, 0x061b, 0x061f, 0x0621, 0x0622, 0x0623,
	0x0624, 0x0625, 0x0626, 0x0627, 0x0628, 0x0629, 0x062a, 0x062b,
	0x062c, 0x062d, 0x062e, 0x062f, 0x0630, 0x0631, 0x0632, 0x0633,
	0x0634, 0x0635, 0x0636, 0x0637, 0x0638, 0x0639, 0x063a, 0x0640,
	0x0641, 0x0642, 0x0643, 0x0644, 0x0645, 0x0646, 0x0647, 0x0648,
	0x0649, 0x064a, 0x064b, 0x064c, 0x064d, 0x064e, 0x064f, 0x0650,
	0x0651, 0x0652
};

/* static struct unipair_str repl_map_iso_8859_6[]; */

static const struct unimapdesc_str dfont_replacedesc_iso_8859_6 = {0,NULL,0,1};
#define UC_CHARSET_SETUP_iso_8859_6 UC_Charset_Setup("iso-8859-6",\
"Arabic (ISO-8859-6)",\
dfont_unicount_iso_8859_6,dfont_unitable_iso_8859_6,146,\
dfont_replacedesc_iso_8859_6,160,2,1089)

#endif /* NO_CHARSET_iso_8859_6 */

#endif /* INCL_CHARSET_iso_8859_6 */