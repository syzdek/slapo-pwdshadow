/*
 *  OpenLDAP pwdPolicy/shadowAccount Overlay
 *  Copyright (c) 2023 David M. Syzdek <david@syzdek.net>
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted only as authorized by the OpenLDAP
 *  Public License.
 *
 *  A copy of this license is available in the file LICENSE in the
 *  top-level directory of the distribution or, alternatively, at
 *  <http://www.OpenLDAP.org/license.html>.
 */
#include "pwdshadow.h"


///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include "portable.h"
#include <ldap.h>
#include "slap.h"
#include "slap-config.h"
#ifdef SLAPD_MODULES
#   include <ltdl.h>
#endif


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#define PWDSHADOW_CFG_DEF_POLICY    0x01

#define PWDSHADOW_OP_UNKNOWN     -2
#define PWDSHADOW_OP_DELETE      -1
#define PWDSHADOW_OP_NONE        0
#define PWDSHADOW_OP_ADD         1

#define PWDSHADOW_FLG_EXISTS     0x0001
#define PWDSHADOW_FLG_USERADD    0x0002
#define PWDSHADOW_FLG_USERDEL    0x0004
#define PWDSHADOW_FLG_EVALADD    0x0008
#define PWDSHADOW_FLG_EVALDEL    0x0010
#define PWDSHADOW_FLG_OVERRIDE   0x0020
//      PWDSHADOW_FLG_UNUSED     0x0040
//      PWDSHADOW_FLG_UNUSED     0x0080
#define PWDSHADOW_TYPE_EXISTS    0x0100
#define PWDSHADOW_TYPE_BOOL      0x0200
#define PWDSHADOW_TYPE_TIME      0x0400
#define PWDSHADOW_TYPE_SECS      0x0800
#define PWDSHADOW_TYPE_DAYS      0x1000
#define PWDSHADOW_TYPE_INTEGER   0x2000
#define PWDSHADOW_TYPE           0xff00
#define PWDSHADOW_OPS            ( PWDSHADOW_FLG_EVALADD | PWDSHADOW_FLG_EVALDEL )
#define PWDSHADOW_STATE          ( PWDSHADOW_FLG_EXISTS | PWDSHADOW_FLG_USERADD | PWDSHADOW_FLG_USERDEL )
#define PWDSHADOW_HAS_MODS       ( PWDSHADOW_DAT_ADD | PWDSHADOW_DAT_DEL )

// query individual flags
#define pwdshadow_flg_useradd(dat)  ((dat)->dat_flag & PWDSHADOW_FLG_USERADD)
#define pwdshadow_flg_userdel(dat)  ((dat)->dat_flag & PWDSHADOW_FLG_USERDEL)
#define pwdshadow_flg_exists(dat)   ((dat)->dat_flag & PWDSHADOW_FLG_EXISTS)
#define pwdshadow_flg_evaladd(dat)  ((dat)->dat_flag & PWDSHADOW_FLG_EVALADD)
#define pwdshadow_flg_evaldel(dat)  ((dat)->dat_flag & PWDSHADOW_FLG_EVALDEL)
#define pwdshadow_flg_override(dat) ((dat)->dat_flag & PWDSHADOW_FLG_OVERRIDE)

// retrieve class of flags
#define pwdshadow_ops(flags)        (flags & PWDSHADOW_OPS)
#define pwdshadow_state(flags)      (flags & PWDSHADOW_STATE)
#define pwdshadow_type(flags)       (flags & PWDSHADOW_TYPE)

// set flags
#define pwdshadow_purge(dat)        (dat)->dat_flag |= ((pwdshadow_flg_exists(dat))) ? PWDSHADOW_FLG_EVALDEL : 0


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

typedef struct pwdshadow_at_t
{
   char *                    def;
   AttributeDescription **   ad;
} pwdshadow_at_t;


typedef struct pwdshadow_data_t
{
   AttributeDescription *     dat_ad;
   int                        dat_flag;
   int                        dat_prev;
   int                        dat_mod;
   int                        dat_post;
} pwdshadow_data_t;


typedef struct pwdshadow_state_t
{
   Entry *                    st_entry;
   int                        st_generate;
   int                        st_purge;

   // slapo-ppolicy attributes (IETF draft-behera-ldap-password-policy-11)
   pwdshadow_data_t           st_pwdChangedTime;
   pwdshadow_data_t           st_pwdEndTime;
   pwdshadow_data_t           st_pwdExpireWarning;
   pwdshadow_data_t           st_pwdGraceExpiry;
   pwdshadow_data_t           st_pwdMaxAge;
   pwdshadow_data_t           st_pwdMinAge;
   pwdshadow_data_t           st_pwdPolicySubentry;

   // slapo-pwdshadow attributes
   pwdshadow_data_t           st_pwdShadowExpire;
   pwdshadow_data_t           st_pwdShadowFlag;
   pwdshadow_data_t           st_pwdShadowGenerate;
   pwdshadow_data_t           st_pwdShadowInactive;
   pwdshadow_data_t           st_pwdShadowLastChange;
   pwdshadow_data_t           st_pwdShadowMax;
   pwdshadow_data_t           st_pwdShadowMin;
   pwdshadow_data_t           st_pwdShadowWarning;

   // LDAP NIS attributes (RFC 2307)
   pwdshadow_data_t           st_shadowExpire;
   pwdshadow_data_t           st_shadowFlag;
   pwdshadow_data_t           st_shadowInactive;
   pwdshadow_data_t           st_shadowLastChange;
   pwdshadow_data_t           st_shadowMax;
   pwdshadow_data_t           st_shadowMin;
   pwdshadow_data_t           st_shadowWarning;

   // User Schema (RFC 2256)
   pwdshadow_data_t           st_userPassword;
} pwdshadow_state_t;


typedef struct pwdshadow_t
{
   struct berval              ps_def_policy;
   int                        ps_cfg_overrides;
   int                        ps_cfg_use_policies;
   int                        ps_cfg_autoexpire;
   pwdshadow_state_t          ps_state;
} pwdshadow_t;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

static int
pwdshadow_cfg_gen(
         ConfigArgs *                  c );


static void
pwdshadow_copy_int_bv(
         int                           i,
         BerValue *                    bv );


static int
pwdshadow_dat_set(
         pwdshadow_data_t *            dat,
         BerValue *                    bv,
         int                           flags );


static int
pwdshadow_dat_value(
         pwdshadow_data_t *            dat,
         int                           val,
         int                           flags );


static int
pwdshadow_db_destroy(
         BackendDB *                   be,
         ConfigReply *                 cr );


static int
pwdshadow_db_init(
         BackendDB *                   be,
         ConfigReply *                 cr );


static int
pwdshadow_eval(
         Operation *                   op,
         pwdshadow_state_t *           st );


static int
pwdshadow_eval_postcheck(
         pwdshadow_data_t *            dat );


static int
pwdshadow_eval_precheck(
         Operation *                   op,
         pwdshadow_state_t *           st,
         pwdshadow_data_t *            dat,
         pwdshadow_data_t *            override,
         pwdshadow_data_t *            triggers[] );


static int
pwdshadow_get_attr(
         Entry *                       entry,
         pwdshadow_data_t *            dat,
         int                           flags );


static int
pwdshadow_get_attrs(
         pwdshadow_t *                 ps,
         pwdshadow_state_t *           st,
         Entry *                       entry,
         int                           flags );


static int
pwdshadow_get_mods(
         Modifications *               mods,
         pwdshadow_data_t *            dat,
         int                           flags );


static int
pwdshadow_op_add(
         Operation *                   op,
         SlapReply *                   rs );


static int
pwdshadow_op_add_attr(
         Entry *                       entry,
         pwdshadow_data_t *            dat );


static int
pwdshadow_op_modify(
         Operation *                   op,
         SlapReply *                   rs );


static int
pwdshadow_op_modify_mods(
         pwdshadow_data_t *            dat,
         Modifications ***             nextp );


static int
pwdshadow_verify_attr_syntax(
         AttributeDescription *        ad,
         const char *                  oid );


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

static slap_overinst pwdshadow;

// internal attribute descriptions
static AttributeDescription *       ad_pwdShadowLastChange  = NULL;
static AttributeDescription *       ad_pwdShadowMin         = NULL;
static AttributeDescription *       ad_pwdShadowMax         = NULL;
static AttributeDescription *       ad_pwdShadowWarning     = NULL;
static AttributeDescription *       ad_pwdShadowInactive    = NULL;
static AttributeDescription *       ad_pwdShadowExpire      = NULL;
static AttributeDescription *       ad_pwdShadowFlag        = NULL;
static AttributeDescription *       ad_pwdShadowGenerate    = NULL;


// # OID Base is iso(1) org(3) dod(6) internet(1) private(4) enterprise(1)
//  dms(27893) software(4) slapo-pwdshadow(2).
//  i.e. slapo-pwdshadow is 1.3.6.1.4.1.27893.4.2
//
//  LDAP operational attribute types are under 1.3.6.1.4.1.27893.4.2.1
//  LDAP user attribute types are under 1.3.6.1.4.1.27893.4.2.2
//  LDAP object classes are under 1.3.6.1.4.1.27893.4.2.3
//  Configuration attribute types are under 1.3.6.1.4.1.27893.4.2.4
//  Configuration object classes are under 1.3.6.1.4.1.27893.4.2.5


// overlay's LDAP operational and user attributes
#pragma mark pwdshadow_ats
static pwdshadow_at_t pwdshadow_ats[] =
{
   {  // pwdShadowLastChange: The number of days since January 1, 1970 on which
      // the password was last changed.  This attribute is the equivalent of
      // 'shadowLastChange'.  The value of this attribute is set when the
      // password is changed and is not calculated at the time of the query.
      .def     = "( 1.3.6.1.4.1.27893.4.2.1.5"
                  " NAME ( 'pwdShadowLastChange' )"
                  " DESC 'The auto-generated value for shadowLastChange'"
                  " EQUALITY integerMatch"
                  " ORDERING integerOrderingMatch"
                  " SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
                  " SINGLE-VALUE"
                  " NO-USER-MODIFICATION"
                  " USAGE directoryOperation )",
      .ad      = &ad_pwdShadowLastChange
   },
   {  // pwdShadowMin: The minimum number of days before a password can be
      // changed.  This attribute is the equivalent of 'shadowMin', but is
      // derived from the value of 'pwdMinAge' in current password policy
      // (pwdMinAge / 60 / 60 /24).
      .def     = "( 1.3.6.1.4.1.27893.4.2.1.6"
                  " NAME ( 'pwdShadowMin' )"
                  " DESC 'The value of pwdMinAge converted for shadowMin'"
                  " EQUALITY integerMatch"
                  " SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
                  " SINGLE-VALUE"
                  " NO-USER-MODIFICATION"
                  " USAGE directoryOperation )",
      .ad      = &ad_pwdShadowMin
   },
   {  // pwdShadowMax: The maximum number of days before a password expires.
      // This attribute is the equivalent of 'shadowMax', but is derived from
      // the value of 'pwdMaxAge' in current password policy (pwdMaxAge / 60 /
      // 60 /24).
      .def     = "( 1.3.6.1.4.1.27893.4.2.1.7"
                  " NAME ( 'pwdShadowMax' )"
                  " DESC 'The value of pwdMaxAge converted for shadowMax'"
                  " EQUALITY integerMatch"
                  " SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
                  " SINGLE-VALUE"
                  " NO-USER-MODIFICATION"
                  " USAGE directoryOperation )",
      .ad      = &ad_pwdShadowMax
   },
   {  // pwdShadowWarning: The number of days before a password expires during
      // which a user should be warned.  This attribute is the equivalent of
      //  'shadowWarning', but is derived from the value of 'pwdExpireWarning'
      // in current password policy (pwdExpireWarning / 60 / 60 /24).
      .def     = "( 1.3.6.1.4.1.27893.4.2.1.8"
                  " NAME ( 'pwdShadowWarning' )"
                  " DESC 'The value of pwdExpireWarning converted for shadowWarning'"
                  " EQUALITY integerMatch"
                  " SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
                  " SINGLE-VALUE"
                  " NO-USER-MODIFICATION"
                  " USAGE directoryOperation )",
      .ad      = &ad_pwdShadowWarning
   },
   {  // pwdShadowInactive: The number of days after a password expires during
      // which the password should still be accepted.  This attribute is the
      // equivalent of 'shadowInactive', but is derived from the value of
      // 'pwdGraceExpiry' in current password policy (pwdGraceExpiry / 60 /
      // 60 /24).
      .def     = "( 1.3.6.1.4.1.27893.4.2.1.9"
                  " NAME ( 'pwdShadowInactive' )"
                  " DESC 'The value of pwdGraceExpiry converted for shadowInactive'"
                  " EQUALITY integerMatch"
                  " SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
                  " SINGLE-VALUE"
                  " NO-USER-MODIFICATION"
                  " USAGE directoryOperation )",
      .ad      = &ad_pwdShadowInactive
   },
   {  // pwdShadowExpire: The number of days after January 1, 1970 on which the
      // account expires. This attribute is the equivalent of 'shadowExpire',
      // but is derived from the value of 'pwdEndTime' of the entry.
      .def     = "( 1.3.6.1.4.1.27893.4.2.1.10"
                  " NAME ( 'pwdShadowExpire' )"
                  " DESC 'The time the password was last changed'"
                  " EQUALITY integerMatch"
                  " ORDERING integerOrderingMatch"
                  " SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
                  " SINGLE-VALUE"
                  " NO-USER-MODIFICATION"
                  " USAGE directoryOperation )",
      .ad      = &ad_pwdShadowExpire
   },
   {  // pwdShadowFlag: This attribute is the equivalent of 'shadowFlag'. This
      // attribute is not used by the overlay and is included so
      // pwdShadowAccount is able to be used as a one for one replacement with
      // shadowAccount.
      .def     = "( 1.3.6.1.4.1.27893.4.2.1.11"
                  " NAME ( 'pwdShadowFlag' )"
                  " EQUALITY integerMatch"
                  " SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
                  " SINGLE-VALUE"
                  " NO-USER-MODIFICATION"
                  " USAGE directoryOperation )",
      .ad      = &ad_pwdShadowFlag
   },
   {  // pwdShadowGenerate: This attribute enables or disables the generation
      // of shadow compatible attributes from the password policy attributes.
      .def     = "( 1.3.6.1.4.1.27893.4.2.2.1"
                  " NAME ( 'pwdShadowGenerate' )"
                  " DESC 'Enables the generation of shadow compatible attributes'"
                  " EQUALITY booleanMatch"
                  " SYNTAX 1.3.6.1.4.1.1466.115.121.1.7"
                  " SINGLE-VALUE "
                  " USAGE directoryOperation )",
      .ad      = &ad_pwdShadowGenerate
   },
   {  
      .def     = NULL,
      .ad      = NULL
   }
};


// overlay's LDAP user object classes
#pragma mark pwdshadow_ocs
static char * pwdshadow_ocs[] =
{
   "( 1.3.6.1.4.1.27893.4.2.3.1"
    " NAME 'pwdShadowAccount'"
    " DESC 'Attributes for controlling pwdShadow overlay'"
    " SUP top"
    " AUXILIARY"
    " MUST ( uid )"
    " MAY ( pwdShadowGenerate ) )",
   NULL
};


// overlay's configuration attribute types
#pragma mark pwdshadow_cfg_ats
static ConfigTable pwdshadow_cfg_ats[] =
{
   {
      .name          = "pwdshadow_default",
      .what          = "policyDN",
      .min_args      = 2,
      .max_args      = 2,
      .length        = 0,
      .arg_type      = ARG_DN|ARG_QUOTE|ARG_MAGIC|PWDSHADOW_CFG_DEF_POLICY,
      .arg_item      = pwdshadow_cfg_gen,
      .attribute     = "( 1.3.6.1.4.1.27893.4.2.4.1"
                        " NAME 'olcPwdShadowDefault'"
                        " DESC 'DN of a pwdPolicy object for uncustomized objects'"
                        " EQUALITY distinguishedNameMatch"
                        " SYNTAX OMsDN"
                        " SINGLE-VALUE )"
   },
   {
      .name          = "pwdshadow_overrides",
      .what          = "on|off",
      .min_args      = 2,
      .max_args      = 2,
      .length        = 0,
      .arg_type      = ARG_ON_OFF|ARG_OFFSET,
      .arg_item      = (void *)offsetof(pwdshadow_t,ps_cfg_overrides),
      .attribute     = "( 1.3.6.1.4.1.27893.4.2.4.2"
                        " NAME 'olcPwdShadowOverrides'"
                        " DESC 'Allow shadow attributes to override the values of generated attribtues.'"
                        " EQUALITY booleanMatch"
                        " SYNTAX OMsBoolean"
                        " SINGLE-VALUE )"
   },
   {
      .name          = "pwdshadow_use_policies",
      .what          = "on|off",
      .min_args      = 2,
      .max_args      = 2,
      .length        = 0,
      .arg_type      = ARG_ON_OFF|ARG_OFFSET,
      .arg_item      = (void *)offsetof(pwdshadow_t,ps_cfg_use_policies),
      .attribute     = "( 1.3.6.1.4.1.27893.4.2.4.3"
                        " NAME 'olcPwdShadowUsePolicies'"
                        " DESC 'Use pwdPolicy to determine values of generated attributes'"
                        " EQUALITY booleanMatch"
                        " SYNTAX OMsBoolean"
                        " SINGLE-VALUE )"
   },
   {
      .name          = "pwdshadow_autoexpire",
      .what          = "on|off",
      .min_args      = 2,
      .max_args      = 2,
      .length        = 0,
      .arg_type      = ARG_ON_OFF|ARG_OFFSET,
      .arg_item      = (void *)offsetof(pwdshadow_t,ps_cfg_autoexpire),
      .attribute     = "( 1.3.6.1.4.1.27893.4.2.4.4"
                        " NAME 'olcPwdShadowAutoExpire'"
                        " DESC 'Use pwdShadowLastChange, pwdMaxAge, and pwdGraceExpiry to generate pwdShadowExpire if pwdEndTime does not exist'"
                        " EQUALITY booleanMatch"
                        " SYNTAX OMsBoolean"
                        " SINGLE-VALUE )"
   },
   {
      .name          = NULL,
      .what          = NULL,
      .min_args      = 0,
      .max_args      = 0,
      .length        = 0,
      .arg_type      = ARG_IGNORED,
      .arg_item      = NULL,
      .attribute     = NULL
   }
};


// overlay's configuration object classes
#pragma mark pwdshadow_cfg_ocs
static ConfigOCs pwdshadow_cfg_ocs[] =
{
   {  .co_def        = "( 1.3.6.1.4.1.27893.4.2.4.1"
                        " NAME 'olcPwdShadowConfig'"
                        " DESC 'Password Shadow configuration'"
                        " SUP olcOverlayConfig"
                        " MAY ( olcPwdShadowDefault $"
                              " olcPwdShadowUsePolicies $"
                              " olcPwdShadowOverrides ) )",
      .co_type       = Cft_Overlay,
      .co_table      = pwdshadow_cfg_ats
   },
   {  .co_def        = NULL,
      .co_type       = 0,
      .co_table      = NULL
   }
};


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

#if SLAPD_OVER_PWDSHADOW == SLAPD_MOD_DYNAMIC
int
init_module(
         int				               argc,
         char *				            argv[] )
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
         ConfigArgs *                  c )
{
   slap_overinst *   on;
   pwdshadow_t *     ps;
   int               rc;

   on    = (slap_overinst *)c->bi;
   ps    = (pwdshadow_t *)on->on_bi.bi_private;
   rc    = ARG_BAD_CONF;

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
         int                           i,
         BerValue *                    bv )
{
   bv->bv_len = snprintf(NULL, 0, "%i", i);
   bv->bv_len++;
   bv->bv_val = ch_malloc( (size_t)bv->bv_len );
   bv->bv_len = snprintf(bv->bv_val, bv->bv_len, "%i", i);
   return;
}


int
pwdshadow_dat_set(
         pwdshadow_data_t *            dat,
         BerValue *                    bv,
         int                           flags )
{
   int                     type;
   int                     ival;
   struct lutil_tm         tm;
   struct lutil_timet      tt;
   AttributeDescription *  ad;

   ad   = dat->dat_ad;
   type = ((pwdshadow_type(dat->dat_flag))) ? pwdshadow_type(dat->dat_flag) : pwdshadow_type(flags);
   if (pwdshadow_type(flags) != type)
      return(-1);

   if ((flags & PWDSHADOW_FLG_USERDEL))
      return(pwdshadow_dat_value(dat, 0, flags));
   if (!(bv))
      return(-1);

   switch(type)
   {
      case PWDSHADOW_TYPE_BOOL:
      if (!(pwdshadow_verify_attr_syntax(ad, "1.3.6.1.4.1.1466.115.121.1.7")))
         return(-1);
      ival = 0;
      if ( ((bv)) && ((bv->bv_val)) && (!(strcasecmp(bv->bv_val, "TRUE"))) )
         ival = 1;
      return(pwdshadow_dat_value(dat, ival, flags));

      case PWDSHADOW_TYPE_DAYS:
      if (!(pwdshadow_verify_attr_syntax(ad, "1.3.6.1.4.1.1466.115.121.1.27")))
         return(-1);
      lutil_atoi(&ival, bv->bv_val);
      return(pwdshadow_dat_value(dat, ival, flags));

      case PWDSHADOW_TYPE_EXISTS:
      ival = ( ((bv)) && ((bv->bv_len)) ) ? 1 : 0;
      return(pwdshadow_dat_value(dat, ival, flags));

      case PWDSHADOW_TYPE_INTEGER:
      if (!(pwdshadow_verify_attr_syntax(ad, "1.3.6.1.4.1.1466.115.121.1.27")))
         return(-1);
      lutil_atoi(&ival, bv->bv_val);
      return(pwdshadow_dat_value(dat, ival, flags));

      case PWDSHADOW_TYPE_SECS:
      if (!(pwdshadow_verify_attr_syntax(ad, "1.3.6.1.4.1.1466.115.121.1.27")))
         return(-1);
      lutil_atoi(&ival, bv->bv_val);
      ival /= 60 * 60 * 24;
      return(pwdshadow_dat_value(dat, ival, flags));

      case PWDSHADOW_TYPE_TIME:
      if (!(pwdshadow_verify_attr_syntax(ad, "1.3.6.1.4.1.1466.115.121.1.24")))
         return(-1);
      if (lutil_parsetime(bv->bv_val, &tm) != 0)
         return(-1);
      lutil_tm2time(&tm, &tt);
      ival = (int)tt.tt_sec;
      ival /= 60 * 60 * 24; // convert from seconds to days
      return(pwdshadow_dat_value(dat, ival, flags));

      default:
      Debug( LDAP_DEBUG_ANY, "pwdshadow: pwdshadow_dat_set(): unknown data type\n" );
      return(-1);
   };

   return(0);
}


int
pwdshadow_dat_value(
         pwdshadow_data_t *            dat,
         int                           val,
         int                           flags )
{
   switch(flags & (PWDSHADOW_FLG_EXISTS|PWDSHADOW_FLG_USERADD|PWDSHADOW_FLG_USERDEL))
   {
      case PWDSHADOW_FLG_EXISTS:
      dat->dat_prev = val;
      dat->dat_post = val;
      break;

      case PWDSHADOW_FLG_USERADD:
      dat->dat_mod  = val;
      dat->dat_post = val;
      break;

      case PWDSHADOW_FLG_USERDEL:
      dat->dat_mod  = 0;
      dat->dat_post = 0;
      break;

      default:
      return(-1);
   };

   dat->dat_flag  |= flags;

   return(0);
}


int
pwdshadow_db_destroy(
         BackendDB *                   be,
         ConfigReply *                 cr )
{
   slap_overinst *   on;
   pwdshadow_t *     ps;

   on                   = (slap_overinst *) be->bd_info;
   ps                   = on->on_bi.bi_private;
   on->on_bi.bi_private = NULL;

   free( ps->ps_def_policy.bv_val );
   free( ps );

   if ((cr))
      return(0);

   return(0);
}


int
pwdshadow_db_init(
         BackendDB *                   be,
         ConfigReply *                 cr )
{
   slap_overinst *         on;
   pwdshadow_t *           ps;
   pwdshadow_state_t *     st;
   const char *            text;

   on = (slap_overinst *) be->bd_info;

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
   on->on_bi.bi_private          = ch_calloc( sizeof(pwdshadow_t), 1 );
   ps                            = on->on_bi.bi_private;
   st                            = &ps->ps_state;

   // set default values
   memset(ps, 0, sizeof(pwdshadow_t));
   ps->ps_cfg_overrides          = 1;
   ps->ps_cfg_use_policies       = 1;
   ps->ps_cfg_autoexpire         = 0;

   // slapo-ppolicy attributes (IETF draft-behera-ldap-password-policy-11)
   slap_str2ad("pwdChangedTime",       &st->st_pwdChangedTime.dat_ad,      &text);
   slap_str2ad("pwdEndTime",           &st->st_pwdEndTime.dat_ad,          &text);
   slap_str2ad("pwdExpireWarning",     &st->st_pwdExpireWarning.dat_ad,    &text);
   slap_str2ad("pwdGraceExpiry",       &st->st_pwdGraceExpiry.dat_ad,      &text);
   slap_str2ad("pwdMaxAge",            &st->st_pwdMaxAge.dat_ad,           &text);
   slap_str2ad("pwdMinAge",            &st->st_pwdMinAge.dat_ad,           &text);
   slap_str2ad("pwdPolicySubentry",    &st->st_pwdPolicySubentry.dat_ad,   &text);

   // slapo-pwdshadow attributes
   slap_str2ad("pwdShadowExpire",      &st->st_pwdShadowExpire.dat_ad,     &text);
   slap_str2ad("pwdShadowFlag",        &st->st_pwdShadowFlag.dat_ad,       &text);
   slap_str2ad("pwdShadowGenerate",    &st->st_pwdShadowGenerate.dat_ad,   &text);
   slap_str2ad("pwdShadowInactive",    &st->st_pwdShadowInactive.dat_ad,   &text);
   slap_str2ad("pwdShadowLastChange",  &st->st_pwdShadowLastChange.dat_ad, &text);
   slap_str2ad("pwdShadowMax",         &st->st_pwdShadowMax.dat_ad,        &text);
   slap_str2ad("pwdShadowMin",         &st->st_pwdShadowMin.dat_ad,        &text);
   slap_str2ad("pwdShadowWarning",     &st->st_pwdShadowWarning.dat_ad,    &text);

   // LDAP NIS attributes (RFC 2307)
   slap_str2ad("shadowExpire",         &st->st_shadowExpire.dat_ad,        &text);
   slap_str2ad("shadowFlag",           &st->st_shadowFlag.dat_ad,          &text);
   slap_str2ad("shadowInactive",       &st->st_shadowInactive.dat_ad,      &text);
   slap_str2ad("shadowLastChange",     &st->st_shadowLastChange.dat_ad,    &text);
   slap_str2ad("shadowMax",            &st->st_shadowMax.dat_ad,           &text);
   slap_str2ad("shadowMin",            &st->st_shadowMin.dat_ad,           &text);
   slap_str2ad("shadowWarning",        &st->st_shadowWarning.dat_ad,       &text);

   // User Schema (RFC 2256)
   if ((st->st_userPassword.dat_ad = slap_schema.si_ad_userPassword) == NULL)
      slap_str2ad("userPassword",      &st->st_userPassword.dat_ad,        &text);

   return(0);
}


int
pwdshadow_eval(
         Operation *                   op,
         pwdshadow_state_t *           st )
{
   pwdshadow_data_t *   dat;

   st->st_purge      = ((pwdshadow_flg_userdel(&st->st_pwdShadowGenerate))) ? 1 : 0;
   st->st_generate   = st->st_pwdShadowGenerate.dat_post;

   // process pwdShadowExpire
   dat = &st->st_pwdShadowExpire;
   pwdshadow_eval_precheck(
      op,
      st,
      dat,                          // data
      &st->st_shadowExpire,         // override attribute
      (pwdshadow_data_t *[])        // triggering attributes
      {  &st->st_pwdEndTime,
         NULL
      }
   );
   pwdshadow_eval_postcheck(dat);

   // process pwdShadowFlag
   dat = &st->st_pwdShadowFlag;
   pwdshadow_eval_precheck(
      op,
      st,
      dat,                          // data
      &st->st_shadowFlag,           // override attribute
      (pwdshadow_data_t *[])        // triggering attributes
      {  NULL
      }
   );
   pwdshadow_eval_postcheck(dat);

   // process pwdShadowInactive
   dat = &st->st_pwdShadowInactive;
   pwdshadow_eval_precheck(
      op,
      st,
      dat,                          // data
      &st->st_shadowInactive,       // override attribute
      (pwdshadow_data_t *[])        // triggering attributes
      {  &st->st_pwdGraceExpiry,
         NULL
      }
   );
   pwdshadow_eval_postcheck(dat);

   // process pwdShadowLastChange
   dat = &st->st_pwdShadowLastChange;
   pwdshadow_eval_precheck(
      op,
      st,
      dat,                          // data
      &st->st_shadowLastChange,     // override attribute
      (pwdshadow_data_t *[])        // triggering attributes
      {  &st->st_userPassword,
         NULL
      }
   );
   if ( ((pwdshadow_flg_evaladd(dat))) && (!(pwdshadow_flg_override(dat))) )
      dat->dat_post = ((int)time(NULL)) / 60 / 60 /24;
   pwdshadow_eval_postcheck(dat);

   // process pwdShadowMax
   dat = &st->st_pwdShadowMax;
   pwdshadow_eval_precheck(
      op,
      st,
      dat,                          // data
      &st->st_shadowMax,            // override attribute
      (pwdshadow_data_t *[])        // triggering attributes
      {  &st->st_pwdMaxAge,
         NULL
      }
   );
   pwdshadow_eval_postcheck(dat);

   // process pwdShadowMin
   dat = &st->st_pwdShadowMin;
   pwdshadow_eval_precheck(
      op,
      st,
      dat,                          // data
      &st->st_shadowMin,            // override attribute
      (pwdshadow_data_t *[])        // triggering attributes
      {  &st->st_pwdMinAge,
         NULL
      }
   );
   pwdshadow_eval_postcheck(dat);

   // process pwdShadowWarning
   dat = &st->st_pwdShadowWarning;
   pwdshadow_eval_precheck(
      op,
      st,
      dat,                          // data
      &st->st_shadowWarning,        // override attribute
      (pwdshadow_data_t *[])        // triggering attributes
      {  &st->st_pwdExpireWarning,
         NULL
      }
   );
   pwdshadow_eval_postcheck(dat);

   return(0);
}


int
pwdshadow_eval_postcheck(
         pwdshadow_data_t *            dat )
{
   if (!(pwdshadow_flg_evaladd(dat)))
      return(0);
   if (!(pwdshadow_flg_exists(dat)))
      return(0);

   if (dat->dat_prev == dat->dat_post)
   {
      dat->dat_flag &= ~PWDSHADOW_FLG_EVALADD;
      return(0);
   };

   return(0);
}


int
pwdshadow_eval_precheck(
         Operation *                   op,
         pwdshadow_state_t *           st,
         pwdshadow_data_t *            dat,
         pwdshadow_data_t *            override,
         pwdshadow_data_t *            triggers[] )
{
   int                     idx;
   int                     should_exist;
   slap_overinst *         on;
   pwdshadow_t *           ps;

   on                = (slap_overinst *)op->o_bd->bd_info;
   ps                = on->on_bi.bi_private;
   should_exist      = 0;

   // determine if overlay is disabled for entry
   if ((st->st_purge))
   {
      pwdshadow_purge(dat);
      return(0);
   };

   // determine if override value is set for attribute
   if ( ((ps->ps_cfg_overrides)) && ((override)) )
   {
      if ((pwdshadow_flg_useradd(override)))
      {
         dat->dat_flag |= (PWDSHADOW_FLG_EVALADD | PWDSHADOW_FLG_OVERRIDE);
         dat->dat_post = override->dat_post;
         return(0);
      };
      if ( ((pwdshadow_flg_exists(override))) && (!(pwdshadow_flg_userdel(override))) )
      {
         if (!(pwdshadow_flg_exists(dat)))
            dat->dat_flag |= PWDSHADOW_FLG_EVALADD;
         dat->dat_flag |= PWDSHADOW_FLG_OVERRIDE;
         dat->dat_post = override->dat_post;
         return(0);
      };
   };

   // check triggers
   for(idx = 0; ( ((triggers)) && ((triggers[idx])) ); idx++)
   {
      if ((pwdshadow_flg_useradd(triggers[idx])))
      {
         dat->dat_flag |= PWDSHADOW_FLG_EVALADD;
         dat->dat_post = triggers[idx]->dat_post;
      } else
      if ( ((pwdshadow_flg_exists(triggers[idx]))) &&
           (!(pwdshadow_flg_userdel(triggers[idx]))) &&
           (!(pwdshadow_flg_exists(dat))) )
      {
         dat->dat_flag |= PWDSHADOW_FLG_EVALADD;
         dat->dat_post = triggers[idx]->dat_post;
      };
      if ( ((pwdshadow_flg_exists(triggers[idx]))) && (!(pwdshadow_flg_userdel(triggers[idx]))) )
         should_exist++;
   };

   // determine if attribute should be removed
   if ( ((pwdshadow_flg_exists(dat))) && (!(should_exist)) )
         dat->dat_flag |= PWDSHADOW_FLG_EVALDEL;

   return(0);
}


int
pwdshadow_get_attr(
         Entry *                       entry,
         pwdshadow_data_t *            dat,
         int                           flags )
{
   Attribute *       a;
   BerValue *        bv;

   if (!(dat->dat_ad))
      return(0);

   if ((a = attr_find(entry->e_attrs, dat->dat_ad)) != NULL)
      a = (a->a_numvals > 0) ? a : NULL;

   bv = ((a)) ? &a->a_nvals[0] : NULL;

   return(pwdshadow_dat_set(dat, bv, flags));
}


int
pwdshadow_get_attrs(
         pwdshadow_t *                 ps,
         pwdshadow_state_t *           st,
         Entry *                       entry,
         int                           flags )
{
   int      flags_bool;
   int      flags_days;
   int      flags_exists;
   int      flags_time;

   if (!(ps))
      return(0);

   flags_bool     = flags | PWDSHADOW_TYPE_BOOL;
   flags_days     = flags | PWDSHADOW_TYPE_DAYS;
   flags_exists   = flags | PWDSHADOW_TYPE_EXISTS;
   flags_time     = flags | PWDSHADOW_TYPE_TIME;

   // slapo-ppolicy attributes (IETF draft-behera-ldap-password-policy-11)
   pwdshadow_get_attr(entry, &st->st_pwdChangedTime,       flags_time);
   pwdshadow_get_attr(entry, &st->st_pwdEndTime,           flags_time);
   pwdshadow_get_attr(entry, &st->st_pwdPolicySubentry,    flags_exists);

   // slapo-pwdshadow attributes
   pwdshadow_get_attr(entry, &st->st_pwdShadowExpire,      flags_days);
   pwdshadow_get_attr(entry, &st->st_pwdShadowGenerate,    flags_bool);
   pwdshadow_get_attr(entry, &st->st_pwdShadowInactive,    flags_days);
   pwdshadow_get_attr(entry, &st->st_pwdShadowLastChange,  flags_days);
   pwdshadow_get_attr(entry, &st->st_pwdShadowMax,         flags_days);
   pwdshadow_get_attr(entry, &st->st_pwdShadowMin,         flags_days);
   pwdshadow_get_attr(entry, &st->st_pwdShadowWarning,     flags_days);

   // LDAP NIS attributes (RFC 2307)
   pwdshadow_get_attr(entry, &st->st_shadowExpire,         flags_days);
   pwdshadow_get_attr(entry, &st->st_shadowFlag,           flags_days);
   pwdshadow_get_attr(entry, &st->st_shadowInactive,       flags_days);
   pwdshadow_get_attr(entry, &st->st_shadowLastChange,     flags_days);
   pwdshadow_get_attr(entry, &st->st_shadowMax,            flags_days);
   pwdshadow_get_attr(entry, &st->st_shadowMin,            flags_days);
   pwdshadow_get_attr(entry, &st->st_shadowWarning,        flags_days);

   // User Schema (RFC 2256)
   pwdshadow_get_attr(entry, &st->st_userPassword,         flags_exists);

   return(0);
}


int
pwdshadow_get_mods(
         Modifications *               mods,
         pwdshadow_data_t *            dat,
         int                           flags )
{
   int                     op;
   BerValue *              bv;

   op    = 0;

   // set attribute description
   dat->dat_ad = ((dat->dat_ad)) ? dat->dat_ad : mods->sml_desc;
   if (dat->dat_ad != mods->sml_desc)
      return(-1);

   // determines and sets operation type
   op = (mods->sml_op == LDAP_MOD_ADD)    ? PWDSHADOW_FLG_USERADD : op;
   op = (mods->sml_op == LDAP_MOD_DELETE) ? PWDSHADOW_FLG_USERDEL : op;
   if (mods->sml_op == LDAP_MOD_REPLACE)
      op = (mods->sml_numvals < 1) ? PWDSHADOW_FLG_USERDEL : PWDSHADOW_FLG_USERADD;
   if (op == 0)
      return(-1);
   flags &= ~(PWDSHADOW_FLG_USERADD | PWDSHADOW_FLG_USERDEL | PWDSHADOW_FLG_EXISTS);
   flags |= op;

   bv = (mods->sml_numvals > 0) ? &mods->sml_values[0]: NULL;

   return(pwdshadow_dat_set(dat, bv, flags));
}


int
pwdshadow_initialize( void )
{
   int               i;
   int               code;

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

   pwdshadow.on_bi.bi_type             = "pwdshadow";
   pwdshadow.on_bi.bi_flags            = SLAPO_BFLAG_SINGLE;

   pwdshadow.on_bi.bi_db_init          = pwdshadow_db_init;
   pwdshadow.on_bi.bi_db_destroy       = pwdshadow_db_destroy;

   pwdshadow.on_bi.bi_op_add          = pwdshadow_op_add;
   pwdshadow.on_bi.bi_op_modify       = pwdshadow_op_modify;

   pwdshadow.on_bi.bi_cf_ocs           = pwdshadow_cfg_ocs;

   return(overlay_register( &pwdshadow ));
}


int
pwdshadow_op_add(
         Operation *                   op,
         SlapReply *                   rs )
{
   slap_overinst *         on;
   pwdshadow_t *           ps;
   pwdshadow_state_t       st;

   // initialize state
   on                = (slap_overinst *)op->o_bd->bd_info;
   ps                = on->on_bi.bi_private;
   memcpy(&st, &ps->ps_state, sizeof(st));

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
         Entry *                       entry,
         pwdshadow_data_t *            dat )
{
   struct berval     bv;
   char              bv_val[128];

   if ( (!(dat->dat_ad)) || (!(dat->dat_flag & PWDSHADOW_FLG_EVALADD)) )
      return(0);

   // convert int to BV
   bv.bv_val = bv_val;
   bv.bv_len = snprintf(bv_val, sizeof(bv_val), "%i", dat->dat_post);

   // add attribute to entry
   attr_merge_one(entry, dat->dat_ad, &bv, &bv);

   return(0);
}


int
pwdshadow_op_modify(
         Operation *                   op,
         SlapReply *                   rs )
{
   int                     rc;
   slap_overinst *         on;
   pwdshadow_t *           ps;
   Modifications *         mods;
   Modifications **        next;
   Entry *                 entry;
   BackendInfo *           bd_info;
   pwdshadow_state_t       st;

   // initialize state
   on                = (slap_overinst *)op->o_bd->bd_info;
   ps                = on->on_bi.bi_private;
   memcpy(&st, &ps->ps_state, sizeof(st));

   // retrieve entry from backend
   bd_info           = op->o_bd->bd_info;
   op->o_bd->bd_info = (BackendInfo *)on->on_info;
   rc                = be_entry_get_rw( op, &op->o_req_ndn, NULL, NULL, 0, &entry );
   op->o_bd->bd_info = (BackendInfo *)bd_info;
   st.st_entry       = entry;
   if ( rc != LDAP_SUCCESS )
      return(SLAP_CB_CONTINUE);

   // determines existing attribtues
   pwdshadow_get_attrs(ps, &st, entry, PWDSHADOW_FLG_EXISTS);

   // scan modifications for attributes of interest
   for(next = &op->orm_modlist; ((*next)); next = &(*next)->sml_next)
   {
      mods = *next;

      if (mods->sml_desc == st.st_pwdEndTime.dat_ad)
         pwdshadow_get_mods(mods, &st.st_pwdEndTime, PWDSHADOW_TYPE_TIME);

      if (mods->sml_desc == st.st_pwdShadowGenerate.dat_ad)
         pwdshadow_get_mods(mods, &st.st_pwdShadowGenerate, PWDSHADOW_TYPE_BOOL);

      if (mods->sml_desc == st.st_userPassword.dat_ad)
         pwdshadow_get_mods(mods, &st.st_userPassword, PWDSHADOW_TYPE_EXISTS);

      // skip remaining attributes if override is disabled
      if (!(ps->ps_cfg_overrides))
         continue;

      if (mods->sml_desc == st.st_shadowExpire.dat_ad)
         pwdshadow_get_mods(mods, &st.st_shadowExpire, PWDSHADOW_TYPE_DAYS);

      if (mods->sml_desc == st.st_shadowFlag.dat_ad)
         pwdshadow_get_mods(mods, &st.st_shadowFlag, PWDSHADOW_TYPE_INTEGER);

      if (mods->sml_desc == st.st_shadowInactive.dat_ad)
         pwdshadow_get_mods(mods, &st.st_shadowInactive, PWDSHADOW_TYPE_DAYS);

      if (mods->sml_desc == st.st_shadowLastChange.dat_ad)
         pwdshadow_get_mods(mods, &st.st_shadowLastChange, PWDSHADOW_TYPE_DAYS);

      if (mods->sml_desc == st.st_shadowMax.dat_ad)
         pwdshadow_get_mods(mods, &st.st_shadowMax, PWDSHADOW_TYPE_DAYS);

      if (mods->sml_desc == st.st_shadowMin.dat_ad)
         pwdshadow_get_mods(mods, &st.st_shadowMin, PWDSHADOW_TYPE_DAYS);

      if (mods->sml_desc == st.st_shadowWarning.dat_ad)
         pwdshadow_get_mods(mods, &st.st_shadowWarning, PWDSHADOW_TYPE_DAYS);
   };

   // evaluate attributes for changes
   pwdshadow_eval(op, &st);

   // processing pwdShadowLastChange
   pwdshadow_op_modify_mods(&st.st_pwdShadowExpire,         &next);
   pwdshadow_op_modify_mods(&st.st_pwdShadowFlag,           &next);
   pwdshadow_op_modify_mods(&st.st_pwdShadowInactive,       &next);
   pwdshadow_op_modify_mods(&st.st_pwdShadowLastChange,     &next);
   pwdshadow_op_modify_mods(&st.st_pwdShadowMax,            &next);
   pwdshadow_op_modify_mods(&st.st_pwdShadowMin,            &next);
   pwdshadow_op_modify_mods(&st.st_pwdShadowWarning,        &next);

   op->o_bd->bd_info = (BackendInfo *)on->on_info;
   be_entry_release_r( op, entry );

   if (!(rs))
      return(SLAP_CB_CONTINUE);

   return(SLAP_CB_CONTINUE);
}


int
pwdshadow_op_modify_mods(
         pwdshadow_data_t *            dat,
         Modifications ***             nextp )
{
   AttributeDescription *  ad;
   Modifications *         mods;

   if ( (!(pwdshadow_ops(dat->dat_flag))) || (!(dat->dat_ad)) )
      return(0);
   ad = dat->dat_ad;

   // create initial modification
   mods  = (Modifications *) ch_malloc( sizeof( Modifications ) );
   mods->sml_op               = LDAP_MOD_DELETE;
   mods->sml_flags            = SLAP_MOD_INTERNAL;
   mods->sml_type.bv_val      = NULL;
   mods->sml_desc             = ad;
   mods->sml_numvals          = 0;
   mods->sml_values           = NULL;
   mods->sml_nvalues          = NULL;
   mods->sml_next             = NULL;
   **nextp                    = mods;
   (*nextp)                   = &mods->sml_next;

   // exit if deleting entry
   if ((pwdshadow_flg_evaldel(dat)))
      return(0);

   // complete modifications for adding/updating value
   mods->sml_op               = LDAP_MOD_REPLACE;
   mods->sml_numvals          = 1;
   mods->sml_values           = ch_calloc( sizeof( struct berval ), 2 );
   pwdshadow_copy_int_bv(dat->dat_post, &mods->sml_values[0]);
   mods->sml_values[1].bv_val = NULL;
   mods->sml_values[1].bv_len = 0;

   return(0);
}


int
pwdshadow_verify_attr_syntax(
         AttributeDescription *        ad,
         const char *                  oid )
{
   const char * syn_oid;

   if (ad == NULL)
      return(0);
   if (ad->ad_type == NULL)
      return(0);
   if (ad->ad_type->sat_syntax == NULL)
      return(0);
   if (ad->ad_type->sat_syntax->ssyn_oid == NULL)
      return(0);
   syn_oid = ad->ad_type->sat_syntax->ssyn_oid;

   if ((strcmp(syn_oid, oid)))
      return(0);

   return(1);
}

/* end of source file */
