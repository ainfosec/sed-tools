#ifndef __SED_TOOLS_UIDS_H__
#define __SED_TOOLS_UIDS_H__
// This file contains ALL (hopefully) the UIDs
// from OPAL Storage Core Architecture spec (v2.0)
// Appendix A

//struct uid_t
//{
//    uint32_t TableUID;
//    uint32_t RowUID;
//};

// The #defines are set up as follows
// #define UID_<Table Name> for UIDs of Tables
// #define UID_<Table Name>_<Row Name> for UIDs of Rows of a Table

/* Templates */
// not used explicitly but for reference
#define TEMPLATE_BASE       0x00
#define TEMPLATE_ADMIN      0x02
#define TEMPLATE_CLOCK      0x04
#define TEMPLATE_CRYPTO     0x06
#define TEMPLATE_LOCKING    0x08
#define TEMPLATE_LOG        0x0A

/* Special Purpose */
#define UID_NULL             0x0000000000000000ll
#define UID_THISSP           0x0100000000000000ll
#define UID_SESSIONMANAGER   0xFF00000000000000ll
#define UID_SMLAYER          0x00FF000000000000ll
#define UID_SMLAYER_PROPERTIES          0x01FF000000000000ll
#define     UID_SMLAYER_STARTSESSION        0x02FF000000000000ll
#define     UID_SMLAYER_SYNCSESSION         0x03FF000000000000ll
#define     UID_SMLAYER_STARTTRUSTEDSESSION 0x04FF000000000000ll
#define     UID_SMLAYER_SYNCTRUSTEDSESSION  0x05FF000000000000ll
#define     UID_SMLAYER_CLOSESESSION        0x06FF000000000000ll
// This next one seems to be a real special case
// and messes with my naming convention
//#define UID_CPIN             0x010000000B000000ll

/* Table + Row UIDs */
// Base Template - 2nd MSB == 0x00
#define UID_TABLE         0x01000000
#define UID_SPINFO        0x02000000
// This is undocument from what I can tell
#define     UID_SPINFO_LOCKINGRANGE     0x0000030002080000ll

#define UID_SPTEMPLATES   0x03000000
#define     UID_SPTEMPLATES_BASE        0x0100000003000000ll
#define     UID_SPTEMPLATES_ADMIN       0x0200000003000000ll
#define     UID_SPTEMPLATES_CLOCK       0x0300000003000000ll
#define     UID_SPTEMPLATES_CRYPTO      0x0400000003000000ll
#define     UID_SPTEMPLATES_LOG         0x0500000003000000ll
#define     UID_SPTEMPLATES_LOCKING     0x0600000003000000ll
// This is undocumented from what I can tell
#define     UID_SPTEMPLATES_MBRCONTROL  0x0100000003080000ll

#define UID_COLUMN        0x04000000
#define UID_TYPE          0x05000000
#define UID_METHOD        0x06000000
            // base template
#define     UID_METHOD_DELETESP         0x0100000006000000ll
#define     UID_METHOD_CREATETABLE      0x0200000006000000ll
#define     UID_METHOD_DELETE           0x0300000006000000ll
#define     UID_METHOD_CREATEROW        0x0400000006000000ll
#define     UID_METHOD_DELETEROW        0x0500000006000000ll
#define     UID_METHOD_NEXT             0x0800000006000000ll
#define     UID_METHOD_GETFREESPACE     0x0900000006000000ll
#define     UID_METHOD_GETFREEROWS      0x0A00000006000000ll
#define     UID_METHOD_DELETEMETHOD     0x0B00000006000000ll
#define     UID_METHOD_GETACL           0x0D00000006000000ll
#define     UID_METHOD_ADDACE           0x0E00000006000000ll
#define     UID_METHOD_REMOVEACE        0x0F00000006000000ll
#define     UID_METHOD_GENKEY           0x1000000006000000ll
#define     UID_METHOD_REVERTSP         0x1100000006000000ll // <- also undocumented
#define     UID_METHOD_GETPACKAGE       0x1200000006000000ll
#define     UID_METHOD_SETPACKAGE       0x1300000006000000ll
#define     UID_METHOD_GET              0x1600000006000000ll
#define     UID_METHOD_SET              0x1700000006000000ll
#define     UID_METHOD_AUTHENTICATE     0x1C00000006000000ll
            // admin template
#define     UID_METHOD_ISSUESP          0x0102000006000000ll
#define     UID_METHOD_REVERTTPER       0x0202000006000000ll // <- undocumented (assholes)
#define     UID_METHOD_ACTIVATE         0x0302000006000000ll
            // clock template
#define     UID_METHOD_GETCLOCK         0x0104000006000000ll
#define     UID_METHOD_RESETCLOCK       0x0204000006000000ll
#define     UID_METHOD_SETCLOCKHIGH     0x0304000006000000ll
#define     UID_METHOD_SETLAGHIGH       0x0404000006000000ll
#define     UID_METHOD_SETCLOCKLOW      0x0504000006000000ll
#define     UID_METHOD_SETLAGLOW        0x0604000006000000ll
#define     UID_METHOD_INCREMENTCOUNTER 0x0704000006000000ll
            // crypto template
#define     UID_METHOD_RANDOM           0x0106000006000000ll
#define     UID_METHOD_SALT             0x0206000006000000ll
#define     UID_METHOD_DECRYPTINIT      0x0306000006000000ll
#define     UID_METHOD_DECRYPT          0x0406000006000000ll
#define     UID_METHOD_DECRYPTFINALIZE  0x0506000006000000ll
#define     UID_METHOD_ENCRYPTINIT      0x0606000006000000ll
#define     UID_METHOD_ENCRYPT          0x0706000006000000ll
#define     UID_METHOD_ENCRYPTFINALIZE  0x0806000006000000ll
#define     UID_METHOD_HMACINIT         0x0906000006000000ll
#define     UID_METHOD_HMAC             0x0A06000006000000ll
#define     UID_METHOD_HMACFINALIZE     0x0B06000006000000ll
#define     UID_METHOD_HASHINIT         0x0C06000006000000ll
#define     UID_METHOD_HASH             0x0D06000006000000ll
#define     UID_METHOD_HASHFINALIZE     0x0E06000006000000ll
#define     UID_METHOD_SIGN             0x0F06000006000000ll
#define     UID_METHOD_VERIFY           0x1006000006000000ll
#define     UID_METHOD_XOR              0x1106000006000000ll
            // log template
#define     UID_METHOD_ADDLOG           0x010A000006000000ll
#define     UID_METHOD_CREATELOG        0x020A000006000000ll
#define     UID_METHOD_CLEARLOG         0x030A000006000000ll
#define     UID_METHOD_FLUSHLOG         0x040A000006000000ll

#define UID_ACCESSCONTROL 0x07000000
#define UID_ACE           0x08000000
// This is undocumented or at least I can't find it
#define     UID_ACE_LOCKINGRANGE_READ   0x00E0030008000000ll
#define     UID_ACE_LOCKINGRANGE_WRITE  0x00E8030008000000ll
#define     UID_ACE_DATASTORE_SET_ALL   0x01FC030008000000ll
#define     UID_ACE_DATASTORE_GET_ALL   0x00FC030008000000ll
#define     UID_ACE_MBRCONTROL_DONE     0x01F8030008000000ll
#define UID_AUTHORITY     0x09000000
            // base template
#define     UID_AUTHORITY_ANYBODY        0x0100000009000000ll
#define     UID_AUTHORITY_ADMINS         0x0200000009000000ll
#define     UID_AUTHORITY_MAKERS         0x0300000009000000ll
#define     UID_AUTHORITY_MAKERSYMK      0x0400000009000000ll
#define     UID_AUTHORITY_MAKERPUK       0x0500000009000000ll
#define     UID_AUTHORITY_SID            0x0600000009000000ll
#define     UID_AUTHORITY_TPERSIGN       0x0700000009000000ll
#define     UID_AUTHORITY_TPEREXCH       0x0800000009000000ll
#define     UID_AUTHORITY_ADMINEXCH      0x0900000009000000ll
            // admin template - 2nd MSB = 0x02
#define     UID_AUTHORITY_ISSUERS        0x0102000009000000ll
#define     UID_AUTHORITY_EDITORS        0x0202000009000000ll
#define     UID_AUTHORITY_DELETERS       0x0302000009000000ll
#define     UID_AUTHORITY_SERVERS        0x0402000009000000ll
#define     UID_AUTHORITY_RESERVE0       0x0502000009000000ll
#define     UID_AUTHORITY_RESERVE1       0x0602000009000000ll
#define     UID_AUTHORITY_RESERVE2       0x0702000009000000ll
#define     UID_AUTHORITY_RESERVE3       0x0802000009000000ll
            // admin template?
#define     UID_AUTHORITY_ADMIN           0x0000010009000000ll
#define     UID_AUTHORITY_ADMIN1           0x0100010009000000ll
            //my guess is admin 2 would be 0x0200010009000000ll
            // user template? 0xXX000300
#define     UID_AUTHORITY_USER           0x0000030009000000ll
#define     UID_AUTHORITY_USER1          0x0100030009000000ll
#define     UID_AUTHORITY_USER2          0x0200030009000000ll

#define UID_CERTIFICATES    0x0A000000
#define UID_CPIN            0x0B000000
#define     UID_CPIN_SID                    0x010000000B000000ll
#define     UID_CPIN_MSID                   0x028400000B000000ll
#define     UID_CPIN_ADMIN                  0x000001000B000000ll
#define     UID_CPIN_ADMIN1                 0x010001000B000000ll
#define     UID_CPIN_USER                   0x000003000B000000ll
#define     UID_CPIN_USER1                  0x010003000B000000ll
#define     UID_CPIN_USER2                  0x020003000B000000ll

#define UID_C_RSA1024       0x0C000000
#define UID_C_RSA2048       0x0D000000
#define UID_C_AES128        0x0E000000
#define UID_C_AES256        0x0F000000
#define UID_C_EC160         0x10000000
#define UID_C_EC192         0x11000000
#define UID_C_EC224         0x12000000
#define UID_C_EC256         0x13000000
#define UID_C_EC384         0x14000000
#define UID_C_EC521         0x15000000
#define UID_C_EC163         0x16000000
#define UID_C_EC233         0x17000000
#define UID_C_EC283         0x18000000
#define UID_C_HMAC160       0x19000000
#define UID_C_HMAC256       0x1A000000
#define UID_C_HMAC384       0x1B000000
#define UID_C_HMAC512       0x1C000000
#define UID_SECRETPROTECT   0x1D000000
/* Not sure how these really work, redefine error
#define     UID_SECRETPROTECT_CPIN              0x010000001D000000ll
#define         UID_SECRETPROTECT_CPIN_COL          0x03
#define     UID_SECRETPROTECT_RSA1024           0x020000001D000000ll
#define         UID_SECRETPROTECT_RSA1024_COL       0x06
#define     UID_SECRETPROTECT_RSA1024           0x030000001D000000ll
#define         UID_SECRETPROTECT_RSA1024_COL       0x07
#define     UID_SECRETPROTECT_RSA1024           0x040000001D000000ll
#define         UID_SECRETPROTECT_RSA1024_COL       0x08
#define     UID_SECRETPROTECT_RSA1024           0x050000001D000000ll
#define         UID_SECRETPROTECT_RSA1024_COL       0x09
#define     UID_SECRETPROTECT_RSA1024           0x060000001D000000ll
#define         UID_SECRETPROTECT_RSA1024_COL       0x0A
#define     UID_SECRETPROTECT_RSA1024           0x070000001D000000ll
#define         UID_SECRETPROTECT_RSA1024_COL       0x0B
#define     UID_SECRETPROTECT_RSA2048           0x080000001D000000ll
#define         UID_SECRETPROTECT_RSA2048_COL       0x06
#define     UID_SECRETPROTECT_RSA2048           0x090000001D000000ll
#define         UID_SECRETPROTECT_RSA2048_COL       0x07
#define     UID_SECRETPROTECT_RSA2048           0x0A0000001D000000ll
#define         UID_SECRETPROTECT_RSA2048_COL       0x08
#define     UID_SECRETPROTECT_RSA2048           0x0B0000001D000000ll
#define         UID_SECRETPROTECT_RSA2048_COL       0x09
#define     UID_SECRETPROTECT_RSA2048           0x0C0000001D000000ll
#define         UID_SECRETPROTECT_RSA2048_COL       0x0A
#define     UID_SECRETPROTECT_RSA2048           0x0D0000001D000000ll
#define         UID_SECRETPROTECT_RSA2048_COL       0x0B
#define     UID_SECRETPROTECT_CAES128           0x0E0000001D000000ll
#define         UID_SECRETPROTECT_CAES128_COL       0x03
#define     UID_SECRETPROTECT_CAES256           0x0F0000001D000000ll
#define         UID_SECRETPROTECT_CAES256_COL       0x03
#define     UID_SECRETPROTECT_EC160             0x100000001D000000ll
#define         UID_SECRETPROTECT_EC160_COL         0x08
#define     UID_SECRETPROTECT_EC192             0x110000001D000000ll
#define         UID_SECRETPROTECT_EC192_COL         0x08
#define     UID_SECRETPROTECT_EC224             0x120000001D000000ll
#define         UID_SECRETPROTECT_EC224_COL         0x08
#define     UID_SECRETPROTECT_EC256             0x130000001D000000ll
#define         UID_SECRETPROTECT_EC256_COL         0x08
#define     UID_SECRETPROTECT_EC384             0x140000001D000000ll
#define         UID_SECRETPROTECT_EC384_COL         0x08
#define     UID_SECRETPROTECT_EC521             0x150000001D000000ll
#define         UID_SECRETPROTECT_EC521_COL         0x08
#define     UID_SECRETPROTECT_EC163             0x160000001D000000ll
#define         UID_SECRETPROTECT_EC163_COL         0x0B
#define     UID_SECRETPROTECT_EC233             0x170000001D000000ll
#define         UID_SECRETPROTECT_EC233_COL         0x09
#define     UID_SECRETPROTECT_EC283             0x180000001D000000ll
#define         UID_SECRETPROTECT_EC283_COL         0x0B
#define     UID_SECRETPROTECT_HMAC160           0x190000001D000000ll
#define         UID_SECRETPROTECT_HMAC160_COL       0x03
#define     UID_SECRETPROTECT_HMAC256           0x1A0000001D000000ll
#define         UID_SECRETPROTECT_HMAC256_COL       0x03
#define     UID_SECRETPROTECT_HMAC384           0x1B0000001D000000ll
#define         UID_SECRETPROTECT_HMAC384_COL       0x03
#define     UID_SECRETPROTECT_HMAC512           0x1C0000001D000000ll
#define         UID_SECRETPROTECT_HMAC512_COL       0x03
#define     UID_SECRETPROTECT_KAES128           0x1D0000001D000000ll
#define         UID_SECRETPROTECT_KAES128_COL       0x03
#define     UID_SECRETPROTECT_KAES256           0x1E0000001D000000ll
#define         UID_SECRETPROTECT_KAES256_COL       0x03
*/

// Admin Template - 2nd MSB = 0x02
#define UID_TPERINFO        0x01020000
#define UID_CRYPTOSUITE     0x03020000
#define UID_TEMPLATE        0x04020000
#define     UID_TEMPLATE_BASE               0x0100000004020000ll
#define     UID_TEMPLATE_ADMIN              0x0200000004020000ll
#define     UID_TEMPLATE_CLOCK              0x0300000004020000ll
#define     UID_TEMPLATE_CRYPTO             0x0400000004020000ll
#define     UID_TEMPLATE_LOG                0x0500000004020000ll
#define     UID_TEMPLATE_LOCKING            0x0600000004020000ll

#define UID_SP              0x05020000
#define     UID_SP_ADMIN                    0x0100000005020000ll
#define     UID_SP_LOCKING                  0x0200000005020000ll

// Clock Template - 2nd MSB = 0x04
#define UID_CLOCKTIME       0x01040000
#define     UID_CLOCKTIME_CLOCK             0x0100000001040000ll

// Crypto Template - 2nd MSB = 0x06
#define UID_H_SHA1          0x01060000
#define UID_H_SHA256        0x02060000
#define UID_H_SHA384        0x03060000
#define UID_H_SHA512        0x04060000

// Locking Template - 2nd MSB = 0x08
#define UID_LOCKINGINFO     0x01080000
#define UID_LOCKING         0x02080000
#define     UID_LOCKING_GLOBALRANGE         0x0100000002080000ll
#define     UID_LOCKING_BAND1               0x0200000002080000ll 
 
#define     RANGE_1                         0x0100030002080000ll
#define     RANGE_2                         0x0200030002080000ll

#define     UID_LOCKING_BAND2               0x0300000002080000ll
#define     UID_LOCKING_BAND3               0x0300000002080000ll

#define UID_MBRCONTROL      0x0100000003080000
#define UID_MBR             0x04080000
#define UID_K_AES128        0x05080000
#define UID_K_AES256        0x06080000

// Log Template - 2nd MSB = 0x0A
#define UID_LOG             0x010A0000
#define UID_LOGLIST         0x010A0000
#define     UID_LOGLIST_LOG                 0x01000000020A0000ll

//Another undocumented uid
#define UID_DATASTORE                       0x0000000001100000ll

// I'm not sure if this is defined anywhere but...
#define HALF_UID_AUTHORITY_OBJECT   0x050C0000
#define HALF_UID_BOOLEAN_ACE        0x0E040000

#endif /* __SED_TOOLS_UIDS_H__ */
