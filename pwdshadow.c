/*
 *  OpenLDAP pwdPolicy/shadowAccount Overlay
 *  Copyright (c) 2023 David M. Syzdek <david@syzdek.net>
 *  All rights reserved.
 *
 *  Dominus vobiscum. Et cum spiritu tuo.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted only as authorized by the OpenLDAP
 *  Public License.
 *
 *  A copy of this license is available in the file LICENSE in the
 *  top-level directory of the distribution or, alternatively, at
 *  <http://www.OpenLDAP.org/license.html>.
 */
#include "portable.h"
#ifdef SLAPD_OVER_PWDSHADOW

///////////////
//           //
//  Headers  //
//           //
///////////////
#ifndef SLAPD_OVER_HELLOWORLD
#	pragma mark - Headers
#endif

#include <ldap.h>
#include "slap.h"
#include "slap-config.h"
#ifdef SLAPD_MODULES
#	include <ltdl.h>
#endif


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#ifndef SLAPD_OVER_HELLOWORLD
#	pragma mark - Definitions
#endif

#define PWDSHADOW_CFG_DEF_POLICY	0x01
#define PWDSHADOW_CFG_POLICY_AD		0x02

#define PWDSHADOW_OP_UNKNOWN		-2
#define PWDSHADOW_OP_DELETE			-1
#define PWDSHADOW_OP_NONE			0
#define PWDSHADOW_OP_ADD			1

#define PWDSHADOW_FLG_EXISTS		0x0001
#define PWDSHADOW_FLG_USERADD		0x0002
#define PWDSHADOW_FLG_USERDEL		0x0004
#define PWDSHADOW_FLG_USERMODS		( PWDSHADOW_FLG_USERADD | PWDSHADOW_FLG_USERDEL )
#define PWDSHADOW_FLG_EVALADD		0x0008
#define PWDSHADOW_FLG_EVALDEL		0x0010
#define PWDSHADOW_FLG_OVERRIDE		0x0020
//PWDSHADOW_FLG_UNUSED				0x0040
//PWDSHADOW_FLG_UNUSED				0x0080
#define PWDSHADOW_TYPE_EXISTS		0x0100
#define PWDSHADOW_TYPE_BOOL			0x0200
#define PWDSHADOW_TYPE_TIME			0x0400
#define PWDSHADOW_TYPE_SECS			0x0800
#define PWDSHADOW_TYPE_DAYS			0x1000
#define PWDSHADOW_TYPE_INTEGER		0x2000
#define PWDSHADOW_TYPE				0xff00
#define PWDSHADOW_OPS				( PWDSHADOW_FLG_EVALADD | PWDSHADOW_FLG_EVALDEL )
#define PWDSHADOW_STATE				( PWDSHADOW_FLG_EXISTS | PWDSHADOW_FLG_USERADD | PWDSHADOW_FLG_USERDEL )
#define PWDSHADOW_HAS_MODS			( PWDSHADOW_DAT_ADD | PWDSHADOW_DAT_DEL )

// query individual flags
#define pwdshadow_flg_useradd(dat)	((dat)->dt_flag & PWDSHADOW_FLG_USERADD)
#define pwdshadow_flg_userdel(dat)	((dat)->dt_flag & PWDSHADOW_FLG_USERDEL)
#define pwdshadow_flg_usermods(dat)	((dat)->dt_flag & PWDSHADOW_FLG_USERMODS)
#define pwdshadow_flg_exists(dat)	((dat)->dt_flag & PWDSHADOW_FLG_EXISTS)
#define pwdshadow_flg_evaladd(dat)	((dat)->dt_flag & PWDSHADOW_FLG_EVALADD)
#define pwdshadow_flg_evaldel(dat)	((dat)->dt_flag & PWDSHADOW_FLG_EVALDEL)
#define pwdshadow_flg_override(dat)	((dat)->dt_flag & PWDSHADOW_FLG_OVERRIDE)

// retrieve class of flags
#define pwdshadow_ops(flags)		(flags & PWDSHADOW_OPS)
#define pwdshadow_state(flags)		(flags & PWDSHADOW_STATE)
#define pwdshadow_type(flags)		(flags & PWDSHADOW_TYPE)

// set flags
#define pwdshadow_purge(dat)		(dat)->dt_flag |= ((pwdshadow_flg_exists(dat))) ? PWDSHADOW_FLG_EVALDEL : 0


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#ifndef SLAPD_OVER_HELLOWORLD
#	pragma mark - Datatypes
#endif

typedef struct pwdshadow_at_t
{
	char *						def;
	AttributeDescription **		ad;
} pwdshadow_at_t;


typedef struct pwdshadow_data_t
{
	AttributeDescription *		dt_ad;
	int							dt_flag;
	int							dt_prev;
	int							dt_mod;
	int							dt_post;
} pwdshadow_data_t;


typedef struct pwdshadow_state_t
{
	BerValue					st_policy;
	int							st_purge;
	int							st_autoexpire;
	pwdshadow_data_t			st_policySubentry;

	// slapo-ppolicy attributes (IETF draft-behera-ldap-password-policy-11)
	pwdshadow_data_t			st_pwdChangedTime;
	pwdshadow_data_t			st_pwdEndTime;
	pwdshadow_data_t			st_pwdExpireWarning;
	pwdshadow_data_t			st_pwdGraceExpiry;
	pwdshadow_data_t			st_pwdMaxAge;
	pwdshadow_data_t			st_pwdMinAge;

	// slapo-pwdshadow policy attributes
	pwdshadow_data_t			st_pwdShadowAutoExpire;

	// slapo-pwdshadow attributes
	pwdshadow_data_t			st_pwdShadowExpire;
	pwdshadow_data_t			st_pwdShadowFlag;
	pwdshadow_data_t			st_pwdShadowGenerate;
	pwdshadow_data_t			st_pwdShadowInactive;
	pwdshadow_data_t			st_pwdShadowLastChange;
	pwdshadow_data_t			st_pwdShadowMax;
	pwdshadow_data_t			st_pwdShadowMin;
	pwdshadow_data_t			st_pwdShadowWarning;

	// LDAP NIS attributes (RFC 2307)
	pwdshadow_data_t			st_shadowExpire;
	pwdshadow_data_t			st_shadowFlag;
	pwdshadow_data_t			st_shadowInactive;
	pwdshadow_data_t			st_shadowLastChange;
	pwdshadow_data_t			st_shadowMax;
	pwdshadow_data_t			st_shadowMin;
	pwdshadow_data_t			st_shadowWarning;

	// User Schema (RFC 2256)
	pwdshadow_data_t			st_userPassword;
} pwdshadow_state_t;


typedef struct pwdshadow_t
{
	struct berval				ps_def_policy;
	int							ps_overrides;
	int							ps_use_policies;
	AttributeDescription *		ps_policy_ad;
} pwdshadow_t;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#ifndef SLAPD_OVER_HELLOWORLD
#	pragma mark - Prototypes
#endif

extern int
init_module(
		int							argc,
		char *						argv[] );


static int
pwdshadow_cfg_gen(
		ConfigArgs *				c );


static void
pwdshadow_copy_int_bv(
		int							i,
		BerValue *					bv );


static int
pwdshadow_db_destroy(
		BackendDB *					be,
		ConfigReply *				cr );


static int
pwdshadow_db_init(
		BackendDB *					be,
		ConfigReply *				cr );


static int
pwdshadow_db_open(
		BackendDB *					be,
		ConfigReply *				cr );


static int
pwdshadow_eval(
		Operation *					op,
		pwdshadow_state_t *			st );


static int
pwdshadow_eval_policy(
		Operation *					op,
		pwdshadow_state_t *			st );


static int
pwdshadow_eval_postcheck(
		pwdshadow_data_t *			dat );


static int
pwdshadow_eval_precheck(
		Operation *					op,
		pwdshadow_state_t *			st,
		pwdshadow_data_t *			dat,
		pwdshadow_data_t *			override,
		pwdshadow_data_t *			triggers[] );


static int
pwdshadow_flg_willexist(
		pwdshadow_data_t *			dat);


static int
pwdshadow_get_attr(
		Entry *						entry,
		pwdshadow_data_t *			dat,
		int							flags );


static int
pwdshadow_get_attrs(
		pwdshadow_t *				ps,
		pwdshadow_state_t *			st,
		Entry *						entry,
		int							flags );


static int
pwdshadow_get_mods(
		Modifications *				mods,
		pwdshadow_data_t *			dat,
		int							flags );


extern int
pwdshadow_initialize(
		void );


static int
pwdshadow_op_add(
		Operation *					op,
		SlapReply *					rs );


static int
pwdshadow_op_add_attr(
		Entry *						entry,
		pwdshadow_data_t *			dat );


static int
pwdshadow_op_modify(
		Operation *					op,
		SlapReply *					rs );


static int
pwdshadow_op_modify_mods(
		pwdshadow_data_t *			dat,
		Modifications ***			nextp );


static int
pwdshadow_set(
		pwdshadow_data_t *			dat,
		BerValue *					bv,
		int							flags );


static int
pwdshadow_set_value(
		pwdshadow_data_t *			dat,
		int							val,
		int							flags );


static int
pwdshadow_state_initialize(
		pwdshadow_state_t *			st,
		pwdshadow_t *				ps );


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#ifndef SLAPD_OVER_HELLOWORLD
#	pragma mark - Variables
#endif

static slap_overinst				pwdshadow;
static ldap_pvt_thread_mutex_t		pwdshadow_ad_mutex;
static int							pwdshadow_schema			= 0;

// internal attribute descriptions
static AttributeDescription *		ad_pwdShadowAutoExpire		= NULL;
static AttributeDescription *		ad_pwdShadowLastChange		= NULL;
static AttributeDescription *		ad_pwdShadowMin				= NULL;
static AttributeDescription *		ad_pwdShadowMax				= NULL;
static AttributeDescription *		ad_pwdShadowWarning			= NULL;
static AttributeDescription *		ad_pwdShadowInactive		= NULL;
static AttributeDescription *		ad_pwdShadowExpire			= NULL;
static AttributeDescription *		ad_pwdShadowFlag			= NULL;
static AttributeDescription *		ad_pwdShadowGenerate		= NULL;
static AttributeDescription *		ad_pwdShadowPolicySubentry	= NULL;

// slapo-ppolicy attributes (IETF draft-behera-ldap-password-policy-11)
static AttributeDescription *		ad_pwdChangedTime			= NULL;
static AttributeDescription *		ad_pwdEndTime				= NULL;
static AttributeDescription *		ad_pwdExpireWarning			= NULL;
static AttributeDescription *		ad_pwdGraceExpiry			= NULL;
static AttributeDescription *		ad_pwdMaxAge				= NULL;
static AttributeDescription *		ad_pwdMinAge				= NULL;

// LDAP NIS attributes (RFC 2307)
static AttributeDescription *		ad_shadowExpire				= NULL;
static AttributeDescription *		ad_shadowFlag				= NULL;
static AttributeDescription *		ad_shadowInactive			= NULL;
static AttributeDescription *		ad_shadowLastChange			= NULL;
static AttributeDescription *		ad_shadowMax				= NULL;
static AttributeDescription *		ad_shadowMin				= NULL;
static AttributeDescription *		ad_shadowWarning			= NULL;

// User Schema (RFC 2256)
static AttributeDescription *		ad_userPassword				= NULL;


// # OID Base is iso(1) org(3) dod(6) internet(1) private(4) enterprise(1)
//	dms(27893) software(4) slapo-pwdshadow(2).
//	i.e. slapo-pwdshadow is 1.3.6.1.4.1.27893.4.2
//
//	LDAP operational attribute types are under 1.3.6.1.4.1.27893.4.2.1
//	LDAP user attribute types are under 1.3.6.1.4.1.27893.4.2.2
//	LDAP object classes are under 1.3.6.1.4.1.27893.4.2.3
//	Configuration attribute types are under 1.3.6.1.4.1.27893.4.2.4
//	Configuration object classes are under 1.3.6.1.4.1.27893.4.2.5


// overlay's LDAP operational and user attributes
static pwdshadow_at_t pwdshadow_ats[] =
{
	{	// pwdShadowLastChange: The number of days since January 1, 1970 on
		// which the password was last changed.  This attribute is the
		// equivalent of 'shadowLastChange'.  The value of this attribute is
		// set when the password is changed and is not calculated at the time
		// of the query.
		.def	= "( 1.3.6.1.4.1.27893.4.2.1.5"
				" NAME ( 'pwdShadowLastChange' )"
				" DESC 'The generated value for shadowLastChange'"
				" EQUALITY integerMatch"
				" ORDERING integerOrderingMatch"
				" SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
				" SINGLE-VALUE"
				" NO-USER-MODIFICATION"
				" USAGE directoryOperation )",
		.ad		= &ad_pwdShadowLastChange
	},
	{	// pwdShadowMin: The minimum number of days before a password can be
		// changed.  This attribute is the equivalent of 'shadowMin', but is
		// derived from the value of 'pwdMinAge' in current password policy
		// (pwdMinAge / 60 / 60 /24).
		.def	= "( 1.3.6.1.4.1.27893.4.2.1.6"
				" NAME ( 'pwdShadowMin' )"
				" DESC 'shadowMin equivalent derived from pwdMinAge'"
				" EQUALITY integerMatch"
				" SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
				" SINGLE-VALUE"
				" NO-USER-MODIFICATION"
				" USAGE directoryOperation )",
		.ad		= &ad_pwdShadowMin
	},
	{	// pwdShadowMax: The maximum number of days before a password expires.
		// This attribute is the equivalent of 'shadowMax', but is derived
		// from the value of 'pwdMaxAge' in current password policy
		// (pwdMaxAge / 60 / 60 /24).
		.def	= "( 1.3.6.1.4.1.27893.4.2.1.7"
				" NAME ( 'pwdShadowMax' )"
				" DESC 'shadowMax equivalent derived from pwdMaxAge'"
				" EQUALITY integerMatch"
				" SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
				" SINGLE-VALUE"
				" NO-USER-MODIFICATION"
				" USAGE directoryOperation )",
		.ad		= &ad_pwdShadowMax
	},
	{	// pwdShadowWarning: The number of days before a password expires
		// during which a user should be warned.  This attribute is the
		// equivalent of 'shadowWarning', but is derived from the value of
		// 'pwdExpireWarning' in current password policy (pwdExpireWarning /
		// 60 / 60 /24).
		.def	= "( 1.3.6.1.4.1.27893.4.2.1.8"
				" NAME ( 'pwdShadowWarning' )"
				" DESC 'shadowWarning equivalent derived from pwdExpireWarning'"
				" EQUALITY integerMatch"
				" SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
				" SINGLE-VALUE"
				" NO-USER-MODIFICATION"
				" USAGE directoryOperation )",
		.ad		= &ad_pwdShadowWarning
	},
	{	// pwdShadowInactive: The number of days after a password expires
		// during which the password should still be accepted.  This attribute
		// is the equivalent of 'shadowInactive', but is derived from the
		// value of 'pwdGraceExpiry' in current password policy
		// (pwdGraceExpiry / 60 / 60 /24).
		.def	= "( 1.3.6.1.4.1.27893.4.2.1.9"
				" NAME ( 'pwdShadowInactive' )"
				" DESC 'shadowInactive equivalent derived from pwdGraceExpiry'"
				" EQUALITY integerMatch"
				" SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
				" SINGLE-VALUE"
				" NO-USER-MODIFICATION"
				" USAGE directoryOperation )",
		.ad		= &ad_pwdShadowInactive
	},
	{	// pwdShadowExpire: The number of days after January 1, 1970 on which
		// the account expires. This attribute is the equivalent of
		// 'shadowExpire', but is derived from the value of 'pwdEndTime' of
		// the entry.
		.def	= "( 1.3.6.1.4.1.27893.4.2.1.10"
				" NAME ( 'pwdShadowExpire' )"
				" DESC 'shadowExpire equivalent derived from pwdEndTime'"
				" EQUALITY integerMatch"
				" ORDERING integerOrderingMatch"
				" SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
				" SINGLE-VALUE"
				" NO-USER-MODIFICATION"
				" USAGE directoryOperation )",
		.ad		= &ad_pwdShadowExpire
	},
	{	// pwdShadowFlag: This attribute is the equivalent of 'shadowFlag'.
		// This attribute is not used by the overlay and is included so
		// pwdShadowAccount is able to be used as a one for one replacement
		// with shadowAccount.
		.def	= "( 1.3.6.1.4.1.27893.4.2.1.11"
				" NAME ( 'pwdShadowFlag' )"
				" DESC 'duplicates shadowFlag'"
				" EQUALITY integerMatch"
				" SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
				" SINGLE-VALUE"
				" NO-USER-MODIFICATION"
				" USAGE directoryOperation )",
		.ad		= &ad_pwdShadowFlag
	},
	{	// pwdShadowGenerate: This attribute enables or disables the
		// generation of shadow compatible attributes from the password policy
		// attributes.
		.def	= "( 1.3.6.1.4.1.27893.4.2.2.1"
				" NAME ( 'pwdShadowGenerate' )"
				" DESC 'generate shadowAccount equivalent attributes'"
				" EQUALITY booleanMatch"
				" SYNTAX 1.3.6.1.4.1.1466.115.121.1.7"
				" SINGLE-VALUE "
				" USAGE directoryOperation )",
		.ad		= &ad_pwdShadowGenerate
	},
	{	// pwdShadowAutoExpire: This attribute, when added to the subentry
		// specified by pwdPolicySubentry, enables the generation of
		// 'pwdShadowExpire' from 'pwdShadowLastChange', 'pwdShadowMax', and
		// 'pwdGraceExpiry' if neither 'shadowExpire' or 'pwdEndTime' are set
		// on the user's entry.
		.def	= "( 1.3.6.1.4.1.27893.4.2.2.2"
				" NAME ( 'pwdShadowAutoExpire' )"
				" DESC 'generate pwdShadowExpire from pwdShadow attributes'"
				" EQUALITY booleanMatch"
				" SYNTAX 1.3.6.1.4.1.1466.115.121.1.7"
				" SINGLE-VALUE )",
		.ad		= &ad_pwdShadowAutoExpire
	},
	{	// pwdShadowPolicySubentry: This attribute specifies the
		// pwdShadowPolicy subentry in effect for this object.  The attribute
		// used to specify the pwdShadowPolicy subentry in affect may be
		// changed using either olcPwdShadowPolicyAttr attribute in the config
		// backend or by the pwdshadow_policy_attr option in slapd.conf.
		.def	= "( 1.3.6.1.4.1.27893.4.2.2.3"
				" NAME ( 'pwdShadowPolicySubentry' )"
				" DESC 'The pwdShadowPolicy subentry in effect for this object'"
				" EQUALITY distinguishedNameMatch"
				" SYNTAX 1.3.6.1.4.1.1466.115.121.1.12"
				" SINGLE-VALUE "
				" USAGE directoryOperation )",
		.ad		= &ad_pwdShadowPolicySubentry
	},
	{
		.def	= NULL,
		.ad		= NULL
	}
};


// overlay's LDAP user object classes
static char * pwdshadow_ocs[] =
{
	"( 1.3.6.1.4.1.27893.4.2.3.1"
	" NAME 'pwdShadowPolicy'"
	" DESC 'Attributes for controlling pwdShadow overlay'"
	" SUP top"
	" AUXILIARY"
	" MAY ( pwdShadowAutoExpire ) )",
	NULL
};


// overlay's configuration attribute types
static ConfigTable pwdshadow_cfg_ats[] =
{
	{	.name		= "pwdshadow_default",
		.what		= "policyDN",
		.min_args	= 2,
		.max_args	= 2,
		.length		= 0,
		.arg_type	= ARG_DN|ARG_QUOTE|ARG_MAGIC|PWDSHADOW_CFG_DEF_POLICY,
		.arg_item	= pwdshadow_cfg_gen,
		.attribute	= "( 1.3.6.1.4.1.27893.4.2.4.1"
					" NAME 'olcPwdShadowDefault'"
					" DESC 'DN of a pwdPolicy object for uncustomized objects'"
					" EQUALITY distinguishedNameMatch"
					" SYNTAX OMsDN"
					" SINGLE-VALUE )"
	},
	{	.name		= "pwdshadow_overrides",
		.what		= "on|off",
		.min_args	= 2,
		.max_args	= 2,
		.length		= 0,
		.arg_type	= ARG_ON_OFF|ARG_OFFSET,
		.arg_item	= (void *)offsetof(pwdshadow_t,ps_overrides),
		.attribute	= "( 1.3.6.1.4.1.27893.4.2.4.2"
					" NAME 'olcPwdShadowOverrides'"
					" DESC 'Allow shadow attributes to override the values of generated attribtues.'"
					" EQUALITY booleanMatch"
					" SYNTAX OMsBoolean"
					" SINGLE-VALUE )"
	},
	{	.name		= "pwdshadow_use_policies",
		.what		= "on|off",
		.min_args	= 2,
		.max_args	= 2,
		.length		= 0,
		.arg_type	= ARG_ON_OFF|ARG_OFFSET,
		.arg_item	= (void *)offsetof(pwdshadow_t,ps_use_policies),
		.attribute	= "( 1.3.6.1.4.1.27893.4.2.4.3"
					" NAME 'olcPwdShadowUsePolicies'"
					" DESC 'Use pwdPolicy to determine values of generated attributes'"
					" EQUALITY booleanMatch"
					" SYNTAX OMsBoolean"
					" SINGLE-VALUE )"
	},
	{	.name		= "pwdshadow_policy_ad",
		.what		= "pwdShadowPolicySubentry attribute",
		.min_args	= 2,
		.max_args	= 2,
		.length		= 0,
		.arg_type	= ARG_MAGIC|ARG_ATDESC|PWDSHADOW_CFG_POLICY_AD,
		.arg_item	= pwdshadow_cfg_gen,
		.attribute	= "( 1.3.6.1.4.1.27893.4.2.4.4"
					" NAME 'olcPwdShadowPolicyAD'"
					" DESC 'Use pwdPolicy to determine values of generated attributes'"
					" EQUALITY caseIgnoreMatch"
					" SYNTAX OMsDirectoryString"
					" SINGLE-VALUE )"
	},
	{	.name		= NULL,
		.what		= NULL,
		.min_args	= 0,
		.max_args	= 0,
		.length	= 0,
		.arg_type	= ARG_IGNORED,
		.arg_item	= NULL,
		.attribute	= NULL
	}
};


// overlay's configuration object classes
static ConfigOCs pwdshadow_cfg_ocs[] =
{
	{	.co_def		= "( 1.3.6.1.4.1.27893.4.2.5.1"
					" NAME 'olcPwdShadowConfig'"
					" DESC 'Password Shadow configuration'"
					" SUP olcOverlayConfig"
					" MAY ( olcPwdShadowDefault $"
						" olcPwdShadowUsePolicies $"
						" olcPwdShadowOverrides ) )",
		.co_type	= Cft_Overlay,
		.co_table	= pwdshadow_cfg_ats
	},
	{	.co_def		= NULL,
		.co_type	= 0,
		.co_table	= NULL
	}
};


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#ifndef SLAPD_OVER_HELLOWORLD
#	pragma mark - Functions
#endif

#if SLAPD_OVER_PWDSHADOW == SLAPD_MOD_DYNAMIC
int
init_module(
		int							argc,
		char *						argv[] )
{
	if ((argc))
		return( pwdshadow_initialize() );
	if ((argv))
		return( pwdshadow_initialize() );
	return( pwdshadow_initialize() );
}
#endif


int
pwdshadow_cfg_gen(
		ConfigArgs *				c )
{
	slap_overinst *			on;
	pwdshadow_t *			ps;
	int						rc;
	AttributeDescription *	ad;

	on		= (slap_overinst *)c->bi;
	ps		= (pwdshadow_t *)on->on_bi.bi_private;
	rc		= ARG_BAD_CONF;

	Debug(LDAP_DEBUG_TRACE, "==> pwdshadow_cfg_gen\n" );

	switch ( c->op )
	{
		case SLAP_CONFIG_EMIT:
		switch( c->type )
		{
			case PWDSHADOW_CFG_DEF_POLICY:
			if ( ps->ps_def_policy.bv_val != NULL)
			{
				if ((rc = value_add_one( &c->rvalue_vals, &ps->ps_def_policy )) != 0)
					return(rc);
				return( value_add_one( &c->rvalue_nvals, &ps->ps_def_policy ) );
			};
			return(0);

			case PWDSHADOW_CFG_POLICY_AD:
			c->value_ad = ps->ps_policy_ad;
			return(0);

			default:
			Debug(LDAP_DEBUG_ANY, "pwdshadow_cfg_gen: unknown configuration option\n" );
			return( ARG_BAD_CONF );
		};
		break;

		case LDAP_MOD_DELETE:
		switch( c->type )
		{
			case PWDSHADOW_CFG_DEF_POLICY:
			Debug(LDAP_DEBUG_TRACE, "==> pwdshadow_cfg_gen delete\n" );
			if ( ps->ps_def_policy.bv_val )
			{
				ber_memfree ( ps->ps_def_policy.bv_val );
				ps->ps_def_policy.bv_val = NULL;
			};
			ps->ps_def_policy.bv_len = 0;
			return(0);

			case PWDSHADOW_CFG_POLICY_AD:
			ps->ps_policy_ad = ad_pwdShadowPolicySubentry;
			return(0);

			default:
			Debug(LDAP_DEBUG_ANY, "pwdshadow_cfg_gen: unknown configuration option\n" );
			return( ARG_BAD_CONF );
		};
		break;

		case SLAP_CONFIG_ADD:
		// fallthru to LDAP_MOD_ADD

		case LDAP_MOD_ADD:
		switch( c->type )
		{
			case PWDSHADOW_CFG_DEF_POLICY:
			Debug(LDAP_DEBUG_TRACE, "==> pwdshadow_cfg_gen add\n" );
			if (( ps->ps_def_policy.bv_val ))
			{
				ber_memfree ( ps->ps_def_policy.bv_val );
			};
			ps->ps_def_policy = c->value_ndn;
			ber_memfree( c->value_dn.bv_val );
			BER_BVZERO( &c->value_dn );
			BER_BVZERO( &c->value_ndn );
			return(0);

			case PWDSHADOW_CFG_POLICY_AD:
			ad = c->value_ad;
			if (!(is_at_syntax(ad->ad_type, SLAPD_DN_SYNTAX)))
			{
				snprintf( c->cr_msg,
							sizeof( c->cr_msg ),
							"pwdshadow_policy_attr attribute=\"%s\" must have DN (%s) syntax",
							c->argv[1],
							SLAPD_DN_SYNTAX );
				Debug(LDAP_DEBUG_CONFIG, "%s: %s.\n", c->log, c->cr_msg);
				return(ARG_BAD_CONF);
			};
			ps->ps_policy_ad = ad;
			return(0);

			default:
			Debug(LDAP_DEBUG_ANY, "pwdshadow_cfg_gen: unknown configuration option\n" );
			return( ARG_BAD_CONF );
		};
		break;
		
		default:
		Debug(LDAP_DEBUG_ANY, "pwdshadow_cfg_gen: unknown configuration operation\n" );
		abort ();
	};

	return(rc);
}


void
pwdshadow_copy_int_bv(
		int							i,
		BerValue *					bv )
{
	bv->bv_len = snprintf(NULL, 0, "%i", i);
	bv->bv_len++;
	bv->bv_val = ch_malloc( (size_t)bv->bv_len );
	bv->bv_len = snprintf(bv->bv_val, bv->bv_len, "%i", i);
	return;
}


int
pwdshadow_db_destroy(
		BackendDB *					be,
		ConfigReply *				cr )
{
	slap_overinst *		on;
	pwdshadow_t *		ps;

	on						= (slap_overinst *) be->bd_info;
	ps						= on->on_bi.bi_private;
	on->on_bi.bi_private	= NULL;

	if ((ps->ps_def_policy.bv_val))
		free(ps->ps_def_policy.bv_val);
	ps->ps_def_policy.bv_val = NULL;

	memset(ps, 0, sizeof(pwdshadow_t));
	ch_free( ps );

	if ((cr))
		return(0);

	return(0);
}


int
pwdshadow_db_init(
		BackendDB *					be,
		ConfigReply *				cr )
{
	slap_overinst *			on;
	pwdshadow_t *			ps;

	if (( SLAP_ISGLOBALOVERLAY( be ) ))
	{
		// do not allow slapo-pwdshadow to be global
		if (( cr ))
		{
			snprintf( cr->msg, sizeof(cr->msg), "slapo-pwdshadow cannot be global" );
			Debug( LDAP_DEBUG_ANY, "%s\n", cr->msg );
		};
		return(1);
	};

	// allocate memory for database instance configuration
	on								= (slap_overinst *) be->bd_info;
	on->on_bi.bi_private			= ch_calloc( sizeof(pwdshadow_t), 1 );
	ps								= on->on_bi.bi_private;

	// set default values
	ps->ps_overrides				= 1;
	ps->ps_use_policies				= 1;
	ps->ps_policy_ad				= ad_pwdShadowPolicySubentry;

	return(0);
}


int
pwdshadow_db_open(
		BackendDB *					be,
		ConfigReply *				cr )
{
	slap_overinst *			on;
	pwdshadow_t *			ps;
	const char *			text;

	on		= (slap_overinst *) be->bd_info;
	ps		= on->on_bi.bi_private;

	ldap_pvt_thread_mutex_lock(&pwdshadow_ad_mutex);

	// verifies schema has not aleady been retrieved
	if ((pwdshadow_schema))
	{
		ldap_pvt_thread_mutex_unlock(&pwdshadow_ad_mutex);
		return(0);
	};
	pwdshadow_schema = 1;

	// slapo-ppolicy attributes (IETF draft-behera-ldap-password-policy-11)
	slap_str2ad("pwdChangedTime",		&ad_pwdChangedTime,		&text);
	slap_str2ad("pwdEndTime",			&ad_pwdEndTime,			&text);
	slap_str2ad("pwdExpireWarning",		&ad_pwdExpireWarning,	&text);
	slap_str2ad("pwdGraceExpiry",		&ad_pwdGraceExpiry,		&text);
	slap_str2ad("pwdMaxAge",			&ad_pwdMaxAge,			&text);
	slap_str2ad("pwdMinAge",			&ad_pwdMinAge,			&text);

	// LDAP NIS attributes (RFC 2307)
	slap_str2ad("shadowExpire",			&ad_shadowExpire,		&text);
	slap_str2ad("shadowFlag",			&ad_shadowFlag,			&text);
	slap_str2ad("shadowInactive",		&ad_shadowInactive,		&text);
	slap_str2ad("shadowLastChange",		&ad_shadowLastChange,	&text);
	slap_str2ad("shadowMax",			&ad_shadowMax,			&text);
	slap_str2ad("shadowMin",			&ad_shadowMin,			&text);
	slap_str2ad("shadowWarning",		&ad_shadowWarning,		&text);

	// User Schema (RFC 2256)
	if ((ad_userPassword = slap_schema.si_ad_userPassword) == NULL)
		slap_str2ad("userPassword",		&ad_userPassword,		&text);

	ldap_pvt_thread_mutex_unlock(&pwdshadow_ad_mutex);

	if ((ps))
		return(0);
	if ((cr))
		return(0);
	return(0);
}


int
pwdshadow_eval(
		Operation *					op,
		pwdshadow_state_t *			st )
{
	int					count;
	slap_overinst *		on;
	pwdshadow_t *		ps;
	pwdshadow_data_t *	dat;

	on					= (slap_overinst *)op->o_bd->bd_info;
	ps					= on->on_bi.bi_private;
	st->st_purge		= ((st->st_pwdShadowGenerate.dt_post)) ? 0 : 1;

	// determine modification count
	count  = 0;
	count += ((pwdshadow_flg_usermods(&st->st_pwdEndTime)))			? 1 : 0;
	count += ((pwdshadow_flg_usermods(&st->st_policySubentry)))		? 1 : 0;
	count += ((pwdshadow_flg_usermods(&st->st_pwdShadowGenerate)))	? 1 : 0;
	count += ((pwdshadow_flg_usermods(&st->st_shadowExpire)))		? 1 : 0;
	count += ((pwdshadow_flg_usermods(&st->st_shadowFlag)))			? 1 : 0;
	count += ((pwdshadow_flg_usermods(&st->st_shadowLastChange)))	? 1 : 0;
	count += ((pwdshadow_flg_usermods(&st->st_shadowMin)))			? 1 : 0;
	count += ((pwdshadow_flg_usermods(&st->st_shadowMax)))			? 1 : 0;
	count += ((pwdshadow_flg_usermods(&st->st_shadowWarning)))		? 1 : 0;
	count += ((pwdshadow_flg_usermods(&st->st_shadowInactive)))		? 1 : 0;
	count += ((pwdshadow_flg_usermods(&st->st_userPassword)))		? 1 : 0;
	if (!(count))
		return(0);

	// retrieve password policy
	if (!(st->st_purge))
		pwdshadow_eval_policy(op, st);

	// process pwdShadowFlag
	dat = &st->st_pwdShadowFlag;
	pwdshadow_eval_precheck(
		op,
		st,
		dat,							// data
		&st->st_shadowFlag,				// override attribute
		NULL							// triggering attributes
	);
	pwdshadow_eval_postcheck(dat);

	// process pwdShadowInactive
	dat = &st->st_pwdShadowInactive;
	pwdshadow_eval_precheck(
		op,
		st,
		dat,							// data
		&st->st_shadowInactive,			// override attribute
		(pwdshadow_data_t *[])			// triggering attributes
		{	&st->st_pwdGraceExpiry,
			NULL
		}
	);
	pwdshadow_eval_postcheck(dat);

	// process pwdShadowLastChange
	dat = &st->st_pwdShadowLastChange;
	pwdshadow_eval_precheck(
		op,
		st,
		dat,							// data
		&st->st_shadowLastChange,		// override attribute
		(pwdshadow_data_t *[])			// triggering attributes
		{	&st->st_userPassword,
			NULL
		}
	);
	if ( ((pwdshadow_flg_evaladd(dat))) && (!(pwdshadow_flg_override(dat))) )
	{
		if ((pwdshadow_flg_useradd(&st->st_userPassword)))
			dat->dt_post = ((int)time(NULL)) / 60 / 60 /24;
		else if ((pwdshadow_flg_exists(&st->st_pwdChangedTime)))
			dat->dt_post = st->st_pwdChangedTime.dt_post;
		else
			dat->dt_post = ((int)time(NULL)) / 60 / 60 /24;
	};
	pwdshadow_eval_postcheck(dat);

	// process pwdShadowMax
	dat = &st->st_pwdShadowMax;
	pwdshadow_eval_precheck(
		op,
		st,
		dat,							// data
		&st->st_shadowMax,				// override attribute
		(pwdshadow_data_t *[])			// triggering attributes
		{	&st->st_pwdMaxAge,
			NULL
		}
	);
	pwdshadow_eval_postcheck(dat);

	// process pwdShadowMin
	dat = &st->st_pwdShadowMin;
	pwdshadow_eval_precheck(
		op,
		st,
		dat,							// data
		&st->st_shadowMin,				// override attribute
		(pwdshadow_data_t *[])			// triggering attributes
		{	&st->st_pwdMinAge,
			NULL
		}
	);
	pwdshadow_eval_postcheck(dat);

	// process pwdShadowWarning
	dat = &st->st_pwdShadowWarning;
	pwdshadow_eval_precheck(
		op,
		st,
		dat,							// data
		&st->st_shadowWarning,			// override attribute
		(pwdshadow_data_t *[])			// triggering attributes
		{	&st->st_pwdExpireWarning,
			NULL
		}
	);
	pwdshadow_eval_postcheck(dat);

	// process pwdShadowExpire
	dat = &st->st_pwdShadowExpire;
	pwdshadow_eval_precheck(
		op,
		st,
		dat,							// data
		&st->st_shadowExpire,			// override attribute
		(pwdshadow_data_t *[])			// triggering attributes
		{	&st->st_pwdShadowLastChange,
			&st->st_pwdShadowAutoExpire,
			&st->st_pwdMaxAge,
			&st->st_pwdGraceExpiry,
			&st->st_pwdEndTime,
			NULL
		}
	);
	if ( ((pwdshadow_flg_evaladd(dat))) && (!(pwdshadow_flg_override(dat))) )
	{
		if ((pwdshadow_flg_willexist(&st->st_pwdEndTime)))
			dat->dt_post = st->st_pwdEndTime.dt_post;
		else if ( ((st->st_autoexpire)) &&
			((pwdshadow_flg_willexist(&st->st_pwdShadowLastChange))) &&
			((pwdshadow_flg_willexist(&st->st_pwdShadowMax))) )
		{
			dat->dt_post =  st->st_pwdShadowLastChange.dt_post;
			dat->dt_post += st->st_pwdShadowMax.dt_post;
			if ((pwdshadow_flg_willexist(&st->st_pwdShadowInactive)))
				dat->dt_post += st->st_pwdShadowInactive.dt_post;
		}
		else
		{
			dat->dt_flag &= ~PWDSHADOW_FLG_EVALADD;
			if ((pwdshadow_flg_exists(dat)))
				dat->dt_flag |= PWDSHADOW_FLG_EVALDEL;
		};
	};
	pwdshadow_eval_postcheck(dat);

	if (!(ps))
		return(0);

	return(0);
}


int
pwdshadow_eval_policy(
		Operation *					op,
		pwdshadow_state_t *			st )
{
	int					rc;
	int					flags;
	slap_overinst *		on;
	pwdshadow_t *		ps;
	BackendDB *			bd_orig;
	Entry *				entry;
	BerVarray			vals;

	on			= (slap_overinst *)op->o_bd->bd_info;
	ps			= on->on_bi.bi_private;
	bd_orig		= op->o_bd;
	entry		= NULL;

	// exit if policies are disabled by the configuration
	if (!(ps->ps_use_policies))
		return(0);

	// attempt to retrieve entry's specific policy
	if ((st->st_policy.bv_val))
	{
		vals = &st->st_policy;
		if ((op->o_bd = select_backend(vals, 0)) != NULL)
		{
			rc = be_entry_get_rw(op, vals, NULL, NULL, 0, &entry);
			if ((rc))
				entry = NULL;
		};
	};

	// attempt to retrieve entry's specific policy
	if ( (!(entry)) && ((ps->ps_def_policy.bv_val)) )
	{
		vals = &ps->ps_def_policy;
		if ((op->o_bd = select_backend(vals, 0)) != NULL)
		{
			rc = be_entry_get_rw(op, vals, NULL, NULL, 0, &entry);
			if ((rc))
				entry = NULL;
		};
	};

	// exit if a policy was not retreived
	if (!(entry))
	{
		op->o_bd = bd_orig;
		return(0);
	};

	// retrieve password policy attributes
	flags = PWDSHADOW_FLG_EXISTS | PWDSHADOW_TYPE_SECS;
	pwdshadow_get_attr(entry, &st->st_pwdExpireWarning,		flags);
	pwdshadow_get_attr(entry, &st->st_pwdGraceExpiry,		flags);
	pwdshadow_get_attr(entry, &st->st_pwdMaxAge,			flags);
	pwdshadow_get_attr(entry, &st->st_pwdMinAge,			flags);
	flags = PWDSHADOW_FLG_EXISTS | PWDSHADOW_TYPE_BOOL;
	pwdshadow_get_attr(entry, &st->st_pwdShadowAutoExpire,	flags);

	if ((pwdshadow_flg_exists(&st->st_pwdShadowAutoExpire)))
		st->st_autoexpire = ((st->st_pwdShadowAutoExpire.dt_post)) ? 1 : 0;

	// release entry
	be_entry_release_r(op, entry);
	op->o_bd = bd_orig;

	return(0);
}


int
pwdshadow_eval_postcheck(
		pwdshadow_data_t *			dat )
{
	if (!(pwdshadow_flg_evaladd(dat)))
		return(0);
	if (!(pwdshadow_flg_exists(dat)))
		return(0);

	if (dat->dt_prev == dat->dt_post)
	{
		dat->dt_flag &= ~PWDSHADOW_FLG_EVALADD;
		return(0);
	};

	return(0);
}


int
pwdshadow_eval_precheck(
		Operation *					op,
		pwdshadow_state_t *			st,
		pwdshadow_data_t *			dat,
		pwdshadow_data_t *			override,
		pwdshadow_data_t *			triggers[] )
{
	int					idx;
	int					should_exist;
	slap_overinst *		on;
	pwdshadow_t *		ps;

	on					= (slap_overinst *)op->o_bd->bd_info;
	ps					= on->on_bi.bi_private;
	should_exist		= 0;

	// determine if overlay is disabled for entry
	if ((st->st_purge))
	{
		pwdshadow_purge(dat);
		return(0);
	};

	// determine if override value is set for attribute
	if ( ((ps->ps_overrides)) && ((override)) )
	{
		if ((pwdshadow_flg_useradd(override)))
		{
			dat->dt_flag |= (PWDSHADOW_FLG_EVALADD | PWDSHADOW_FLG_OVERRIDE);
			dat->dt_post = override->dt_post;
			return(0);
		};
		if ( ((pwdshadow_flg_exists(override))) && (!(pwdshadow_flg_userdel(override))) )
		{
			dat->dt_flag |= (PWDSHADOW_FLG_EVALADD | PWDSHADOW_FLG_OVERRIDE);
			dat->dt_post = override->dt_post;
			return(0);
		};
	};

	// check triggers
	for(idx = 0; ( ((triggers)) && ((triggers[idx])) ); idx++)
	{
		if ((pwdshadow_flg_useradd(triggers[idx])))
		{
			dat->dt_flag |= PWDSHADOW_FLG_EVALADD;
			dat->dt_post = triggers[idx]->dt_post;
		} else
		if ( ((pwdshadow_flg_exists(triggers[idx]))) &&
			(!(pwdshadow_flg_userdel(triggers[idx]))) )
		{
			dat->dt_flag |= PWDSHADOW_FLG_EVALADD;
			dat->dt_post = triggers[idx]->dt_post;
		};
		if ( ((pwdshadow_flg_exists(triggers[idx]))) && (!(pwdshadow_flg_userdel(triggers[idx]))) )
			should_exist++;
		else if ((pwdshadow_flg_useradd(triggers[idx])))
			should_exist++;
	};

	// determine if attribute should be removed
	if ( ((pwdshadow_flg_exists(dat))) && (!(should_exist)) )
			dat->dt_flag |= PWDSHADOW_FLG_EVALDEL;

	return(0);
}


int
pwdshadow_flg_willexist(
		pwdshadow_data_t *			dat )
{
	if ((dat->dt_flag & PWDSHADOW_FLG_EVALDEL))
		return(0);
	if ((dat->dt_flag & PWDSHADOW_FLG_USERDEL))
		return(0);
	if ((dat->dt_flag & PWDSHADOW_FLG_EXISTS))
		return(1);
	if ((dat->dt_flag & PWDSHADOW_FLG_USERADD))
		return(1);
	if ((dat->dt_flag & PWDSHADOW_FLG_EVALADD))
		return(1);
	return(0);
}


int
pwdshadow_get_attr(
		Entry *						entry,
		pwdshadow_data_t *			dat,
		int							flags )
{
	Attribute *			a;
	BerValue *			bv;

	if (!(dat->dt_ad))
		return(0);

	if ((a = attr_find(entry->e_attrs, dat->dt_ad)) != NULL)
		a = (a->a_numvals > 0) ? a : NULL;

	bv = ((a)) ? &a->a_nvals[0] : NULL;

	return(pwdshadow_set(dat, bv, flags));
}


int
pwdshadow_get_attrs(
		pwdshadow_t *				ps,
		pwdshadow_state_t *			st,
		Entry *						entry,
		int							flags )
{
	int						flags_bool;
	int						flags_days;
	int						flags_exists;
	int						flags_time;
	int						flags_integer;
	Attribute *				a;
	AttributeDescription *	ad;

	if (!(ps))
		return(0);

	flags_bool		= flags | PWDSHADOW_TYPE_BOOL;
	flags_days		= flags | PWDSHADOW_TYPE_DAYS;
	flags_exists	= flags | PWDSHADOW_TYPE_EXISTS;
	flags_time		= flags | PWDSHADOW_TYPE_TIME;
	flags_integer	= flags | PWDSHADOW_TYPE_INTEGER;

	// slapo-ppolicy policy subentry
	pwdshadow_get_attr(entry, &st->st_policySubentry,		flags_exists);

	// slapo-ppolicy attributes (IETF draft-behera-ldap-password-policy-11)
	pwdshadow_get_attr(entry, &st->st_pwdChangedTime,		flags_time);
	pwdshadow_get_attr(entry, &st->st_pwdEndTime,			flags_time);

	// slapo-pwdshadow attributes
	pwdshadow_get_attr(entry, &st->st_pwdShadowExpire,		flags_days);
	pwdshadow_get_attr(entry, &st->st_pwdShadowFlag,		flags_integer);
	pwdshadow_get_attr(entry, &st->st_pwdShadowGenerate,	flags_bool);
	pwdshadow_get_attr(entry, &st->st_pwdShadowInactive,	flags_days);
	pwdshadow_get_attr(entry, &st->st_pwdShadowLastChange,	flags_days);
	pwdshadow_get_attr(entry, &st->st_pwdShadowMax,			flags_days);
	pwdshadow_get_attr(entry, &st->st_pwdShadowMin,			flags_days);
	pwdshadow_get_attr(entry, &st->st_pwdShadowWarning,		flags_days);

	// LDAP NIS attributes (RFC 2307)
	pwdshadow_get_attr(entry, &st->st_shadowExpire,			flags_days);
	pwdshadow_get_attr(entry, &st->st_shadowFlag,			flags_integer);
	pwdshadow_get_attr(entry, &st->st_shadowInactive,		flags_days);
	pwdshadow_get_attr(entry, &st->st_shadowLastChange,		flags_days);
	pwdshadow_get_attr(entry, &st->st_shadowMax,			flags_days);
	pwdshadow_get_attr(entry, &st->st_shadowMin,			flags_days);
	pwdshadow_get_attr(entry, &st->st_shadowWarning,		flags_days);

	// User Schema (RFC 2256)
	pwdshadow_get_attr(entry, &st->st_userPassword,			flags_exists);

	// update pwdPolicy
	if ((ps->ps_use_policies))
	{
		ad = st->st_policySubentry.dt_ad;
		if ((a = attr_find(entry->e_attrs, ad)) != NULL)
		{
			if ((a = (a->a_numvals > 0) ? a : NULL) != NULL)
			{
				st->st_policy.bv_len = a->a_nvals[0].bv_len;
				st->st_policy.bv_val = a->a_nvals[0].bv_val;
			};
		};
	};

	return(0);
}


int
pwdshadow_get_mods(
		Modifications *				mods,
		pwdshadow_data_t *			dat,
		int							flags )
{
	int						op;
	BerValue *				bv;

	// set attribute description
	dat->dt_ad = ((dat->dt_ad)) ? dat->dt_ad : mods->sml_desc;
	if (dat->dt_ad != mods->sml_desc)
		return(-1);

	// determines and sets operation type
	op = 0;
	op = (mods->sml_op == LDAP_MOD_ADD)		? PWDSHADOW_FLG_USERADD : op;
	op = (mods->sml_op == LDAP_MOD_DELETE)	? PWDSHADOW_FLG_USERDEL : op;
	if (mods->sml_op == LDAP_MOD_REPLACE)
		op = (mods->sml_numvals < 1) ? PWDSHADOW_FLG_USERDEL : PWDSHADOW_FLG_USERADD;
	if (op == 0)
		return(-1);
	flags &= ~(PWDSHADOW_FLG_USERADD | PWDSHADOW_FLG_USERDEL | PWDSHADOW_FLG_EXISTS);
	flags |= op;

	bv = (mods->sml_numvals > 0) ? &mods->sml_values[0]: NULL;

	return(pwdshadow_set(dat, bv, flags));
}


int
pwdshadow_initialize( void )
{
	int					i;
	int					code;

	for(i = 0; ((pwdshadow_ats[i].def)); i++)
	{
		if ((code = register_at(pwdshadow_ats[i].def, pwdshadow_ats[i].ad, 0)) != 0)
		{
			Debug( LDAP_DEBUG_ANY, "pwdshadow_initialize: register_at failed\n" );
			return(code);
		};
		if ((is_at_no_user_mod((*pwdshadow_ats[i].ad)->ad_type)))
		{
			(*pwdshadow_ats[i].ad)->ad_type->sat_flags |= SLAP_AT_MANAGEABLE;
		};
	};

	for (i = 0; ((pwdshadow_ocs[i])); i++)
	{
		if ((code = register_oc( pwdshadow_ocs[i], NULL, 0 )) != 0)
		{
			Debug( LDAP_DEBUG_ANY, "pwdshadow_initialize: register_oc failed\n");
			return(code);
		};
	};

	if ((code = config_register_schema( pwdshadow_cfg_ats, pwdshadow_cfg_ocs )) != 0)
	{
		Debug( LDAP_DEBUG_ANY, "pwdshadow_initialize: config_register_schema failed\n");
		return(code);
	};

	ldap_pvt_thread_mutex_init(&pwdshadow_ad_mutex);

	pwdshadow.on_bi.bi_type			= "pwdshadow";
	pwdshadow.on_bi.bi_flags		= SLAPO_BFLAG_SINGLE;

	pwdshadow.on_bi.bi_db_init		= pwdshadow_db_init;
	pwdshadow.on_bi.bi_db_open		= pwdshadow_db_open;
	pwdshadow.on_bi.bi_db_destroy	= pwdshadow_db_destroy;

	pwdshadow.on_bi.bi_op_add		= pwdshadow_op_add;
	pwdshadow.on_bi.bi_op_modify	= pwdshadow_op_modify;

	pwdshadow.on_bi.bi_cf_ocs		= pwdshadow_cfg_ocs;

	return(overlay_register( &pwdshadow ));
}


int
pwdshadow_op_add(
		Operation *					op,
		SlapReply *					rs )
{
	slap_overinst *			on;
	pwdshadow_t *			ps;
	pwdshadow_state_t		st;

	// initialize state
	on						= (slap_overinst *)op->o_bd->bd_info;
	ps						= on->on_bi.bi_private;
	pwdshadow_state_initialize(&st, ps);


	// determines existing attribtues
	pwdshadow_get_attrs(ps, &st, op->ora_e, PWDSHADOW_FLG_USERADD);

	// evaluate attributes for changes
	pwdshadow_eval(op, &st);

	// processing changes
	pwdshadow_op_add_attr(op->ora_e, &st.st_pwdShadowExpire);
	pwdshadow_op_add_attr(op->ora_e, &st.st_pwdShadowFlag);
	pwdshadow_op_add_attr(op->ora_e, &st.st_pwdShadowInactive);
	pwdshadow_op_add_attr(op->ora_e, &st.st_pwdShadowLastChange);
	pwdshadow_op_add_attr(op->ora_e, &st.st_pwdShadowMax);
	pwdshadow_op_add_attr(op->ora_e, &st.st_pwdShadowMin);
	pwdshadow_op_add_attr(op->ora_e, &st.st_pwdShadowWarning);

	if (!(rs))
		return(SLAP_CB_CONTINUE);

	return(SLAP_CB_CONTINUE);
}


int
pwdshadow_op_add_attr(
		Entry *						entry,
		pwdshadow_data_t *			dat )
{
	struct berval	bv;
	char			bv_val[128];

	if ((pwdshadow_flg_usermods(dat)))
		return(0);
	if ( (!(dat->dt_ad)) || (!(dat->dt_flag & PWDSHADOW_FLG_EVALADD)) )
		return(0);

	// convert int to BV
	bv.bv_val = bv_val;
	bv.bv_len = snprintf(bv_val, sizeof(bv_val), "%i", dat->dt_post);

	// add attribute to entry
	attr_merge_one(entry, dat->dt_ad, &bv, &bv);

	return(0);
}


int
pwdshadow_op_modify(
		Operation *					op,
		SlapReply *					rs )
{
	int						rc;
	slap_overinst *			on;
	pwdshadow_t *			ps;
	Modifications *			mods;
	Modifications **		next;
	Entry *					entry;
	BackendInfo *			bd_info;
	pwdshadow_state_t		st;

	// initialize state
	on					= (slap_overinst *)op->o_bd->bd_info;
	ps					= on->on_bi.bi_private;
	pwdshadow_state_initialize(&st, ps);

	// retrieve entry from backend
	bd_info				= op->o_bd->bd_info;
	op->o_bd->bd_info	= (BackendInfo *)on->on_info;
	rc					= be_entry_get_rw( op, &op->o_req_ndn, NULL, NULL, 0, &entry );
	op->o_bd->bd_info	= (BackendInfo *)bd_info;
	if ( rc != LDAP_SUCCESS )
		return(SLAP_CB_CONTINUE);

	// determines existing attribtues
	pwdshadow_get_attrs(ps, &st, entry, PWDSHADOW_FLG_EXISTS);

	// release entry
	op->o_bd->bd_info = (BackendInfo *)on->on_info;
	be_entry_release_r( op, entry );
	op->o_bd->bd_info = (BackendInfo *)bd_info;

	// scan modifications for attributes of interest
	for(next = &op->orm_modlist; ((*next)); next = &(*next)->sml_next)
	{
		mods = *next;

		if (mods->sml_desc == st.st_pwdEndTime.dt_ad)
			pwdshadow_get_mods(mods, &st.st_pwdEndTime, PWDSHADOW_TYPE_TIME);

		if (mods->sml_desc == st.st_pwdShadowExpire.dt_ad)
			pwdshadow_get_mods(mods, &st.st_pwdShadowExpire, PWDSHADOW_TYPE_DAYS);

		if (mods->sml_desc == st.st_pwdShadowFlag.dt_ad)
			pwdshadow_get_mods(mods, &st.st_pwdShadowFlag, PWDSHADOW_TYPE_INTEGER);

		if (mods->sml_desc == st.st_pwdShadowGenerate.dt_ad)
			pwdshadow_get_mods(mods, &st.st_pwdShadowGenerate, PWDSHADOW_TYPE_BOOL);

		if (mods->sml_desc == st.st_pwdShadowInactive.dt_ad)
			pwdshadow_get_mods(mods, &st.st_pwdShadowInactive, PWDSHADOW_TYPE_DAYS);

		if (mods->sml_desc == st.st_pwdShadowLastChange.dt_ad)
			pwdshadow_get_mods(mods, &st.st_pwdShadowLastChange, PWDSHADOW_TYPE_DAYS);

		if (mods->sml_desc == st.st_pwdShadowMax.dt_ad)
			pwdshadow_get_mods(mods, &st.st_pwdShadowMax, PWDSHADOW_TYPE_DAYS);

		if (mods->sml_desc == st.st_pwdShadowMin.dt_ad)
			pwdshadow_get_mods(mods, &st.st_pwdShadowMin, PWDSHADOW_TYPE_DAYS);

		if (mods->sml_desc == st.st_pwdShadowWarning.dt_ad)
			pwdshadow_get_mods(mods, &st.st_pwdShadowWarning, PWDSHADOW_TYPE_DAYS);

		if (mods->sml_desc == st.st_userPassword.dt_ad)
			pwdshadow_get_mods(mods, &st.st_userPassword, PWDSHADOW_TYPE_EXISTS);

		if (mods->sml_desc == st.st_policySubentry.dt_ad)
		{
			pwdshadow_get_mods(mods, &st.st_policySubentry, PWDSHADOW_TYPE_EXISTS);
			if ((pwdshadow_flg_userdel(&st.st_policySubentry)))
			{
				st.st_policy.bv_len = 0;
				st.st_policy.bv_val = NULL;
			};
			if ((pwdshadow_flg_useradd(&st.st_policySubentry)))
			{
				st.st_policy.bv_len = mods->sml_values[0].bv_len;
				st.st_policy.bv_val = mods->sml_values[0].bv_val;
			};
		};

		// skip remaining attributes if override is disabled
		if (!(ps->ps_overrides))
			continue;

		if (mods->sml_desc == st.st_shadowExpire.dt_ad)
			pwdshadow_get_mods(mods, &st.st_shadowExpire, PWDSHADOW_TYPE_DAYS);

		if (mods->sml_desc == st.st_shadowFlag.dt_ad)
			pwdshadow_get_mods(mods, &st.st_shadowFlag, PWDSHADOW_TYPE_INTEGER);

		if (mods->sml_desc == st.st_shadowInactive.dt_ad)
			pwdshadow_get_mods(mods, &st.st_shadowInactive, PWDSHADOW_TYPE_DAYS);

		if (mods->sml_desc == st.st_shadowLastChange.dt_ad)
			pwdshadow_get_mods(mods, &st.st_shadowLastChange, PWDSHADOW_TYPE_DAYS);

		if (mods->sml_desc == st.st_shadowMax.dt_ad)
			pwdshadow_get_mods(mods, &st.st_shadowMax, PWDSHADOW_TYPE_DAYS);

		if (mods->sml_desc == st.st_shadowMin.dt_ad)
			pwdshadow_get_mods(mods, &st.st_shadowMin, PWDSHADOW_TYPE_DAYS);

		if (mods->sml_desc == st.st_shadowWarning.dt_ad)
			pwdshadow_get_mods(mods, &st.st_shadowWarning, PWDSHADOW_TYPE_DAYS);
	};

	// evaluate attributes for changes
	pwdshadow_eval(op, &st);

	// processing pwdShadowLastChange
	pwdshadow_op_modify_mods(&st.st_pwdShadowExpire,		&next);
	pwdshadow_op_modify_mods(&st.st_pwdShadowFlag,			&next);
	pwdshadow_op_modify_mods(&st.st_pwdShadowInactive,		&next);
	pwdshadow_op_modify_mods(&st.st_pwdShadowLastChange,	&next);
	pwdshadow_op_modify_mods(&st.st_pwdShadowMax,			&next);
	pwdshadow_op_modify_mods(&st.st_pwdShadowMin,			&next);
	pwdshadow_op_modify_mods(&st.st_pwdShadowWarning,		&next);

	if (!(rs))
		return(SLAP_CB_CONTINUE);

	return(SLAP_CB_CONTINUE);
}


int
pwdshadow_op_modify_mods(
		pwdshadow_data_t *			dat,
		Modifications ***			nextp )
{
	AttributeDescription *	ad;
	Modifications *			mods;

	if ((pwdshadow_flg_usermods(dat)))
		return(0);
	if ( (!(pwdshadow_ops(dat->dt_flag))) || (!(dat->dt_ad)) )
		return(0);
	ad = dat->dt_ad;

	// create initial modification
	mods = (Modifications *) ch_malloc( sizeof( Modifications ) );
	mods->sml_op				= LDAP_MOD_DELETE;
	mods->sml_flags				= SLAP_MOD_INTERNAL;
	mods->sml_type.bv_val		= NULL;
	mods->sml_desc				= ad;
	mods->sml_numvals			= 0;
	mods->sml_values			= NULL;
	mods->sml_nvalues			= NULL;
	mods->sml_next				= NULL;
	**nextp						= mods;
	(*nextp)					= &mods->sml_next;

	// exit if deleting entry
	if ((pwdshadow_flg_evaldel(dat)))
		return(0);

	// complete modifications for adding/updating value
	mods->sml_op				= LDAP_MOD_REPLACE;
	mods->sml_numvals			= 1;
	mods->sml_values			= ch_calloc( sizeof( struct berval ), 2 );
	pwdshadow_copy_int_bv(dat->dt_post, &mods->sml_values[0]);
	mods->sml_values[1].bv_val	= NULL;
	mods->sml_values[1].bv_len	= 0;

	return(0);
}


int
pwdshadow_set(
		pwdshadow_data_t *			dat,
		BerValue *					bv,
		int							flags )
{
	int						type;
	int						ival;
	struct lutil_tm			tm;
	struct lutil_timet		tt;
	AttributeDescription *	ad;

	ad		= dat->dt_ad;
	type	= ((pwdshadow_type(dat->dt_flag))) ? pwdshadow_type(dat->dt_flag) : pwdshadow_type(flags);
	if (pwdshadow_type(flags) != type)
		return(-1);

	if ((flags & PWDSHADOW_FLG_USERDEL))
		return(pwdshadow_set_value(dat, 0, flags));
	if (!(bv))
		return(-1);

	switch(type)
	{
		case PWDSHADOW_TYPE_BOOL:
		if (!(is_at_syntax(ad->ad_type, "1.3.6.1.4.1.1466.115.121.1.7")))
			return(-1);
		ival = 0;
		if ( ((bv)) && ((bv->bv_val)) && (!(strcasecmp(bv->bv_val, "TRUE"))) )
			ival = 1;
		return(pwdshadow_set_value(dat, ival, flags));

		case PWDSHADOW_TYPE_DAYS:
		if (!(is_at_syntax(ad->ad_type, SLAPD_INTEGER_SYNTAX)))
			return(-1);
		lutil_atoi(&ival, bv->bv_val);
		return(pwdshadow_set_value(dat, ival, flags));

		case PWDSHADOW_TYPE_EXISTS:
		ival = ( ((bv)) && ((bv->bv_len)) ) ? 1 : 0;
		return(pwdshadow_set_value(dat, ival, flags));

		case PWDSHADOW_TYPE_INTEGER:
		if (!(is_at_syntax(ad->ad_type, SLAPD_INTEGER_SYNTAX)))
			return(-1);
		lutil_atoi(&ival, bv->bv_val);
		return(pwdshadow_set_value(dat, ival, flags));

		case PWDSHADOW_TYPE_SECS:
		if (!(is_at_syntax(ad->ad_type, SLAPD_INTEGER_SYNTAX)))
			return(-1);
		lutil_atoi(&ival, bv->bv_val);
		ival /= 60 * 60 * 24;
		return(pwdshadow_set_value(dat, ival, flags));

		case PWDSHADOW_TYPE_TIME:
		if (!(is_at_syntax(ad->ad_type, "1.3.6.1.4.1.1466.115.121.1.24")))
			return(-1);
		if (lutil_parsetime(bv->bv_val, &tm) != 0)
			return(-1);
		lutil_tm2time(&tm, &tt);
		ival = (int)tt.tt_sec;
		ival /= 60 * 60 * 24; // convert from seconds to days
		return(pwdshadow_set_value(dat, ival, flags));

		default:
		Debug( LDAP_DEBUG_ANY, "pwdshadow: pwdshadow_set(): unknown data type\n" );
		return(-1);
	};

	return(0);
}


int
pwdshadow_set_value(
		pwdshadow_data_t *			dat,
		int							val,
		int							flags )
{
	int op;

	op  = PWDSHADOW_FLG_EXISTS;
	op |= PWDSHADOW_FLG_USERADD;
	op |= PWDSHADOW_FLG_USERDEL;
	switch(flags & op)
	{
		case PWDSHADOW_FLG_EXISTS:
		dat->dt_prev = val;
		dat->dt_post = val;
		break;

		case PWDSHADOW_FLG_USERADD:
		dat->dt_mod  = val;
		dat->dt_post = val;
		break;

		case PWDSHADOW_FLG_USERDEL:
		dat->dt_mod  = 0;
		dat->dt_post = 0;
		break;

		default:
		return(-1);
	};

	dat->dt_flag  |= flags;

	return(0);
}


int
pwdshadow_state_initialize(
		pwdshadow_state_t *			st,
		pwdshadow_t *				ps )
{
	memset(st, 0, sizeof(pwdshadow_state_t));

	st->st_policySubentry.dt_ad			= ps->ps_policy_ad;

	ldap_pvt_thread_mutex_lock(&pwdshadow_ad_mutex);

	// slapo-pwdshadow policy attributes
	st->st_pwdShadowAutoExpire.dt_ad	= ad_pwdShadowAutoExpire;

	// slapo-pwdshadow attributes
	st->st_pwdShadowExpire.dt_ad		= ad_pwdShadowExpire;
	st->st_pwdShadowFlag.dt_ad			= ad_pwdShadowFlag;
	st->st_pwdShadowGenerate.dt_ad		= ad_pwdShadowGenerate;
	st->st_pwdShadowInactive.dt_ad		= ad_pwdShadowInactive;
	st->st_pwdShadowLastChange.dt_ad	= ad_pwdShadowLastChange;
	st->st_pwdShadowMax.dt_ad			= ad_pwdShadowMax;
	st->st_pwdShadowMin.dt_ad			= ad_pwdShadowMin;
	st->st_pwdShadowWarning.dt_ad		= ad_pwdShadowWarning;

	// slapo-ppolicy attributes (IETF draft-behera-ldap-password-policy-11)
	st->st_pwdChangedTime.dt_ad			= ad_pwdChangedTime;
	st->st_pwdEndTime.dt_ad				= ad_pwdEndTime;
	st->st_pwdExpireWarning.dt_ad		= ad_pwdExpireWarning;
	st->st_pwdGraceExpiry.dt_ad			= ad_pwdGraceExpiry;
	st->st_pwdMaxAge.dt_ad				= ad_pwdMaxAge;
	st->st_pwdMinAge.dt_ad				= ad_pwdMinAge;

	// LDAP NIS attributes (RFC 2307)
	st->st_shadowExpire.dt_ad			= ad_shadowExpire;
	st->st_shadowFlag.dt_ad				= ad_shadowFlag;
	st->st_shadowInactive.dt_ad			= ad_shadowInactive;
	st->st_shadowLastChange.dt_ad		= ad_shadowLastChange;
	st->st_shadowMax.dt_ad				= ad_shadowMax;
	st->st_shadowMin.dt_ad				= ad_shadowMin;
	st->st_shadowWarning.dt_ad			= ad_shadowWarning;

	// User Schema (RFC 2256)
	st->st_userPassword.dt_ad			= ad_userPassword;

	ldap_pvt_thread_mutex_unlock(&pwdshadow_ad_mutex);

	return(0);
}

#endif
/* end of source file */
