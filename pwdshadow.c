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

#define PWDSHADOW_DEF_POLICY     0x01


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////

typedef struct pwdshadow_t
{
   struct berval              ps_def_policy;
   AttributeDescription *     ps_ad_pwdChangedTime;
   AttributeDescription *     ps_ad_pwdEndTime;
   AttributeDescription *     ps_ad_shadowExpire;
   AttributeDescription *     ps_ad_shadowLastChange;
   AttributeDescription *     ps_ad_shadowMax;
   AttributeDescription *     ps_ad_userPassword;
   int                        ps_cfg_override;
   int                        ps_cfg_realtime;
} pwdshadow_t;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

static int
pwdshadow_attr_bool(
      Entry *                          entry,
      AttributeDescription *           ad );


static int
pwdshadow_attr_exists(
      Entry *                          entry,
      AttributeDescription *           ad );


static int
pwdshadow_attr_integer(
      Entry *                          entry,
      AttributeDescription *           ad);


static int
pwdshadow_attr_time(
      Entry *                          entry,
      AttributeDescription *           ad );


static int
pwdshadow_cfg_gen(
        ConfigArgs *                    c );


static int
pwdshadow_db_destroy(
        BackendDB *                     be,
        ConfigReply *                   cr );


static int
pwdshadow_db_init(
        BackendDB *                     be,
        ConfigReply *                   cr );


static int
pwdshadow_op_search(
         Operation *                   op,
         SlapReply *                   rs );


static int
pwdshadow_parse_bool(
         BerValue *                    bv );


static time_t
pwdshadow_parse_time(
         char *                        atm );


static int
pwdshadow_verify_attr_syntax(
      AttributeDescription *           ad,
      const char *                     oid );


/////////////////
//             //
//  Variables  //
//             //
/////////////////

static slap_overinst pwdshadow;


// external attribute descriptions
static AttributeDescription *       ad_pwdChangedTime       = NULL;
static AttributeDescription *       ad_pwdEndTime           = NULL;
static AttributeDescription *       ad_shadowExpire         = NULL;
static AttributeDescription *       ad_shadowLastChange     = NULL;
static AttributeDescription *       ad_userPassword         = NULL;


// external internal descriptions
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
static struct
{
   char *                    def;
   AttributeDescription **   ad;
} pwdshadow_ats[] =
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
static ConfigTable pwdshadow_cfg_ats[] =
{
   {
      .name          = "pwdshadow_default",
      .what          = "policyDN",
      .min_args      = 2,
      .max_args      = 2,
      .length        = 0,
      .arg_type      = ARG_DN|ARG_QUOTE|ARG_MAGIC|PWDSHADOW_DEF_POLICY,
      .arg_item      = pwdshadow_cfg_gen,
      .attribute     = "( 1.3.6.1.4.1.27893.4.2.4.1"
                        " NAME 'olcPwdShadowDefault'"
                        " DESC 'DN of a pwdPolicy object for uncustomized objects'"
                        " EQUALITY distinguishedNameMatch"
                        " SYNTAX OMsDN"
                        " SINGLE-VALUE )",
      .ad            = NULL,
      .arg_default   = NULL
   },
   {
      .name          = "pwdshadow_override",
      .what          = "on|off",
      .min_args      = 2,
      .max_args      = 2,
      .length        = 0,
      .arg_type      = ARG_ON_OFF|ARG_OFFSET,
      .arg_item      = (void *)offsetof(pwdshadow_t,ps_cfg_override),
      .attribute     = "( 1.3.6.1.4.1.27893.4.2.4.3"
                        " NAME 'olcPwdShadowOverride'"
                        " DESC 'Attribute which indicates shadow attributes should be generated'"
                        " EQUALITY booleanMatch"
                        " SYNTAX OMsBoolean"
                        " SINGLE-VALUE )",
      .ad            = NULL,
      .arg_default   = NULL
   },
   {
      .name          = "pwdshadow_realtime",
      .what          = "on|off",
      .min_args      = 2,
      .max_args      = 2,
      .length        = 0,
      .arg_type      = ARG_ON_OFF|ARG_OFFSET,
      .arg_item      = (void *)offsetof(pwdshadow_t,ps_cfg_realtime),
      .attribute     = "( 1.3.6.1.4.1.27893.4.2.4.4"
                        " NAME 'olcPwdShadowRealTime'"
                        " DESC 'Attribute which indicates shadow attributes should be generated in realtime'"
                        " EQUALITY booleanMatch"
                        " SYNTAX OMsBoolean"
                        " SINGLE-VALUE )",
      .ad            = NULL,
      .arg_default   = NULL
   },
   {
      .name          = NULL,
      .what          = NULL,
      .min_args      = 0,
      .max_args      = 0,
      .length        = 0,
      .arg_type      = ARG_IGNORED
   }
};


// overlay's configuration object classes
static ConfigOCs pwdshadow_cfg_ocs[] =
{
   {  .co_def        = "( 1.3.6.1.4.1.27893.4.2.4.1"
                        " NAME 'olcPwdShadowConfig'"
                        " DESC 'Password Shadow configuration'"
                        " SUP olcOverlayConfig"
                        " MAY ( olcPwdShadowDefault $"
                              " olcPwdShadowOverride $"
                              " olcPwdShadowRealTime ) )",
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

#if SLAPD_OVER_PWDSHADOW == SLAPD_MOD_DYNAMIC
int
init_module(
	int				argc,
	char *				argv[] )
{
   if ((argc))
      return( pwdshadow_initialize() );
   if ((argv))
      return( pwdshadow_initialize() );
   return( pwdshadow_initialize() );
}
#endif


int
pwdshadow_attr_bool(
      Entry *                          entry,
      AttributeDescription *           ad)
{
   Attribute *       a;

   if (!(ad))
      return(0);
   if ((a = attr_find(entry->e_attrs, ad)) == NULL)
      return(0);
   if (a->a_numvals == 0)
      return(0);

   // process attribute as Boolean
   if ((pwdshadow_verify_attr_syntax(ad, "1.3.6.1.4.1.1466.115.121.1.7")))
      return(pwdshadow_parse_bool(&a->a_nvals[0]));

   return(1);
}


int
pwdshadow_attr_exists(
      Entry *                          entry,
      AttributeDescription *           ad )
{
   Attribute *       a;

   if (!(ad))
      return(0);
   if ((a = attr_find(entry->e_attrs, ad)) == NULL)
      return(0);
   if (a->a_numvals == 0)
      return(0);
   if (a->a_nvals[0].bv_len == 0)
      return(0);

   return(1);
}


int
pwdshadow_attr_integer(
      Entry *                          entry,
      AttributeDescription *           ad)
{
   Attribute *       a;
   int               i;

   if (!(ad))
      return(0);
   if ((a = attr_find(entry->e_attrs, ad)) == NULL)
      return(0);
   if (a->a_numvals == 0)
      return(0);

   // process attribute as Integer
   if ((pwdshadow_verify_attr_syntax(ad, "1.3.6.1.4.1.1466.115.121.1.27")))
   {
      lutil_atoi(&i, a->a_nvals[0].bv_val);
      return(i);
   };

   return(0);
}


int
pwdshadow_attr_time(
      Entry *                          entry,
      AttributeDescription *           ad)
{
   Attribute *       a;
   time_t            t;
   int               i;

   if (!(ad))
      return(0);
   if ((a = attr_find(entry->e_attrs, ad)) == NULL)
      return(0);
   if (a->a_numvals == 0)
      return(0);

   // process attribute as Generalized Time
   if ((pwdshadow_verify_attr_syntax(ad, "1.3.6.1.4.1.1466.115.121.1.24")))
   {
      if ((t = pwdshadow_parse_time(a->a_nvals[0].bv_val)) == ((time_t)-1))
         return(0);
      t /= 60; // convert to minutes
      t /= 60; // convert to hours
      t /= 24; // convert to days
      return((int)t);
   };

   // process attribute as Integer
   if ((pwdshadow_verify_attr_syntax(ad, "1.3.6.1.4.1.1466.115.121.1.27")))
   {
      i = 0;
      lutil_atoi(&i, a->a_nvals[0].bv_val);
      return(i);
   };

   return(0);
}


int
pwdshadow_cfg_gen(
        ConfigArgs *                    c )
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
         case PWDSHADOW_DEF_POLICY:
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
         case PWDSHADOW_DEF_POLICY:
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
         case PWDSHADOW_DEF_POLICY:
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


int
pwdshadow_db_destroy(
        BackendDB *                     be,
        ConfigReply *                   cr )
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
        BackendDB *                     be,
        ConfigReply *                   cr )
{
   slap_overinst *   on;
   pwdshadow_t *     ps;
   const char *      text;

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
   ps->ps_cfg_override           = 1;
   ps->ps_cfg_realtime           = 0;

   // retrieve attribute descriptions
   if ((ps->ps_ad_pwdChangedTime = ad_pwdChangedTime) == NULL)
      slap_str2ad("pwdChangedTime", &ps->ps_ad_pwdChangedTime, &text);
   if ((ps->ps_ad_pwdEndTime = ad_pwdEndTime) == NULL)
      slap_str2ad("pwdEndTime", &ps->ps_ad_pwdEndTime, &text);
   if ((ps->ps_ad_shadowExpire = ad_shadowExpire) == NULL)
      slap_str2ad("shadowExpire", &ps->ps_ad_shadowExpire, &text);
   if ((ps->ps_ad_shadowLastChange = ad_shadowLastChange) == NULL)
      slap_str2ad("shadowLastChange", &ps->ps_ad_shadowLastChange, &text);
   if ((ps->ps_ad_userPassword = ad_userPassword) == NULL)
      slap_str2ad("userPassword", &ps->ps_ad_userPassword, &text);

   return(0);
}


int
pwdshadow_initialize( void )
{
   int               i;
   int               code;
   const char *      text;

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

   slap_str2ad("pwdChangedTime",       &ad_pwdChangedTime,     &text);
   slap_str2ad("pwdEndTime",           &ad_pwdEndTime,         &text);
   slap_str2ad("shadowExpire",         &ad_shadowExpire,       &text);
   slap_str2ad("shadowLastChange",     &ad_shadowLastChange,   &text);
   ad_userPassword                     = slap_schema.si_ad_userPassword;

   pwdshadow.on_bi.bi_type             = "pwdshadow";
   pwdshadow.on_bi.bi_flags            = SLAPO_BFLAG_SINGLE;

   pwdshadow.on_bi.bi_db_init          = pwdshadow_db_init;
   //pwdshadow.on_bi.bi_db_open         = pwdshadow_db_open;
   //pwdshadow.on_bi.bi_db_close        = pwdshadow_db_close;
   pwdshadow.on_bi.bi_db_destroy       = pwdshadow_db_destroy;

   //pwdshadow.on_bi.bi_op_add          = pwdshadow_add;
   //pwdshadow.on_bi.bi_op_bind         = pwdshadow_bind;
   //pwdshadow.on_bi.bi_op_compare      = pwdshadow_compare;
   //pwdshadow.on_bi.bi_op_delete       = pwdshadow_restrict;
   //pwdshadow.on_bi.bi_op_modify       = pwdshadow_modify;
   pwdshadow.on_bi.bi_op_search       = pwdshadow_op_search;

   //pwdshadow.on_bi.bi_connection_destroy = pwdshadow_connection_destroy;

   pwdshadow.on_bi.bi_cf_ocs           = pwdshadow_cfg_ocs;

   return(overlay_register( &pwdshadow ));
}


int
pwdshadow_op_search(
         Operation *                   op,
         SlapReply *                   rs )
{
   slap_overinst *         on;
   pwdshadow_t *           ps;

   // initialize state
   on                = (slap_overinst *)op->o_bd->bd_info;
   ps                = on->on_bi.bi_private;

   if (!(rs))
      return(SLAP_CB_CONTINUE);
   if (!(ps->ps_cfg_realtime))
      return(SLAP_CB_CONTINUE);

   return(SLAP_CB_CONTINUE);
}


int
pwdshadow_parse_bool(
         BerValue *                    bv )
{
   if ( (!(bv)) || (!(bv->bv_val)) )
      return(0);
   if (!(strcasecmp(bv->bv_val, "TRUE")))
      return(1);
   return(0);
}


time_t
pwdshadow_parse_time(
         char *                        atm )
{
   struct lutil_tm         tm;
   struct lutil_timet      tt;
   time_t                  ret;

   ret = (time_t)-1;

   if ( lutil_parsetime( atm, &tm ) == 0)
   {
      lutil_tm2time( &tm, &tt );
      ret = tt.tt_sec;
   };
   return(ret);
}


int
pwdshadow_verify_attr_syntax(
      AttributeDescription *           ad,
      const char *                     oid )
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
