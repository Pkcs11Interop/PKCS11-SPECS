/* Define API */
#ifndef _PKCS11_H_
#define _PKCS11_H_ 1

#ifndef FALSE
#define FALSE             0
#endif

#ifndef TRUE
#define TRUE              (!FALSE)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* All the various Cryptoki types and #define'd values are in the file
 * pkcs11t.h.  CK_PTR should be defined there, too; it's the recipe for
 * making pointers. */
#include "pkcs11t.h"

#define __PASTE(x,y)      x##y

/* =================================================================
 * Define the "extern" form of all the entry points */

#define CK_EXTERN         extern
#define CK_FUNC(name)     CK_ENTRY name
#define CK_NEED_ARG_LIST  1
#define _CK_RV            CK_RV

/* pkcs11f.h has all the information about the Cryptoki functions. */
#include "pkcs11f.h"

#undef CK_FUNC
#undef CK_EXTERN
#undef CK_NEED_ARG_LIST
#undef _CK_RV

/* =================================================================
 * Define the typedef form of all the entry points.
 * That is, for each Cryptoki function C_XXX, define a type CK_C_XXX
 * which is a pointer to that kind of function. */

#define CK_EXTERN         typedef
#define CK_FUNC(name)     CK_ENTRY (CK_PTR __PASTE(CK_,name))
#define CK_NEED_ARG_LIST  1
#define _CK_RV            CK_RV

#include "pkcs11f.h"

#undef CK_FUNC
#undef CK_EXTERN
#undef CK_NEED_ARG_LIST
#undef _CK_RV

/* =================================================================
 * Define structed vector of entry points.
 * The CK_FUNCTION_LIST contains a CK_VERSION indicating the Cryptoki
 * version, and then a whole slew of function pointers to the routines
 * in the library.  This type was declared, but not defined, in
 * pkcs11t.h. */


/* These data types are platform/implementation dependent. */
#if defined(WINDOWS) 
#if defined(_WIN32)
#define CK_ENTRY          __declspec( dllexport )
#define CK_PTR            *
#define NULL_PTR          0
#pragma pack(push, cryptoki, 1)
#else /* win16 */
#define CK_ENTRY          _export _far _pascal
#define CK_PTR            far *
#define NULL_PTR          0
#pragma pack(push, cryptoki, 1)
#endif
#else /* not windows */
#define CK_ENTRY
#define CK_PTR            *
#define NULL_PTR          0
#endif


#define CK_EXTERN 
#define CK_FUNC(name)     __PASTE(CK_,name) name;
#define _CK_RV

struct CK_FUNCTION_LIST {

  CK_VERSION    version;  /* Cryptoki version */

/* Pile all the function pointers into it. */
#include "pkcs11f.h"

};

#undef CK_FUNC
#undef CK_EXTERN
#undef _CK_RV


#if defined(WINDOWS)
#pragma pack(pop, cryptoki)
#endif


#undef __PASTE
/* ================================================================= */

#ifdef __cplusplus
}
#endif

#endif
