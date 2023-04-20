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

#define PSHADOW_DEFAULT       0x01
#define PSHADOW_GENATTR       0x02


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////

typedef struct pwdshadow_info
{
   struct berval        def_policy;
   char *               genattr;
   int                  override;
   int                  realtime;
} pwdshadow_info;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

static int
pshadow_cf_default(
        ConfigArgs *                    c );


static int
pshadow_db_destroy(
        BackendDB *                     be,
        ConfigReply *                   cr );


static int
pshadow_db_init(
        BackendDB *                     be,
        ConfigReply *                   cr );


/////////////////
//             //
//  Variables  //
//             //
/////////////////

static slap_overinst pshadow;


// # OID Base is iso(1) org(3) dod(6) internet(1) private(4) enterprise(1)
//  dms(27893) software(4) slapo-pwdshadow(2).
//  i.e. slapo-pwdshadow is 1.3.6.1.4.1.27893.4.2
//
//  LDAP operational attribute types are under 1.3.6.1.4.1.27893.4.2.1
//  LDAP user attribute types are under 1.3.6.1.4.1.27893.4.2.2
//  LDAP object classes are under 1.3.6.1.4.1.27893.4.2.3
//  Configuration attribute types are under 1.3.6.1.4.1.27893.4.2.4
//  Configuration object classes are under 1.3.6.1.4.1.27893.4.2.5


static AttributeDescription *       ad_pwdShadowLastChange;
static AttributeDescription *       ad_pwdShadowMin;
static AttributeDescription *       ad_pwdShadowMax;
static AttributeDescription *       ad_pwdShadowWarning;
static AttributeDescription *       ad_pwdShadowInactive;
static AttributeDescription *       ad_pwdShadowExpire;
static AttributeDescription *       ad_pwdShadowFlag;
static AttributeDescription *       ad_pwdShadowGenerate;


static struct
{
   char *                    def;
   AttributeDescription **   ad;
} pshadow_ats[] =
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


static char * pshadow_ocs[] =
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


static ConfigTable pshadow_cfg_ats[] =
{
   {
      .name          = "pwdshadow_default",
      .what          = "policyDN",
      .min_args      = 2,
      .max_args      = 2,
      .length        = 0,
      .arg_type      = ARG_DN|ARG_QUOTE|ARG_MAGIC|PSHADOW_DEFAULT,
      .arg_item      = pshadow_cf_default,
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
      .name          = "pwdshadow_genattr",
      .what          = "pwdshadowGenerationAttribute",
      .min_args      = 2,
      .max_args      = 2,
      .length        = 0,
      .arg_type      = ARG_MAGIC|PSHADOW_GENATTR,
      .arg_item      = pshadow_cf_default,
      .attribute     = "( 1.3.6.1.4.1.27893.4.2.4.2"
                        " NAME 'olcPwdShadowGenerationAttribute'"
                        " DESC 'Attribute which indicates shadow attributes should be generated'"
                        " EQUALITY distinguishedNameMatch"
                        " SYNTAX OMsDN"
                        " SINGLE-VALUE )",
   },
   {
      .name          = "pwdshadow_override",
      .what          = "on|off",
      .min_args      = 2,
      .max_args      = 2,
      .length        = 0,
      .arg_type      = ARG_ON_OFF|ARG_OFFSET,
      .arg_item      = (void *)offsetof(pwdshadow_info,override),
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
      .arg_item      = (void *)offsetof(pwdshadow_info,realtime),
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


static ConfigOCs pshadow_cfg_ocs[] =
{
   {  .co_def        = "( 1.3.6.1.4.1.27893.4.2.4.1"
                        " NAME 'olcPwdShadowConfig'"
                        " DESC 'Password Shadow configuration'"
                        " SUP olcOverlayConfig"
                        " MAY ( olcPwdShadowDefault $"
                              " olcPwdShadowGenerationAttribute $"
                              " olcPwdShadowOverride $"
                              " olcPwdShadowRealTime ) )",
      .co_type       = Cft_Overlay,
      .co_table      = pshadow_cfg_ats
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

#if SLAPD_OVER_PSHADOW == SLAPD_MOD_DYNAMIC
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
pshadow_cf_default(
        ConfigArgs *                    c )
{
   slap_overinst *   on;
   pwdshadow_info *  psinfo;
   int               rc;

   on     = (slap_overinst *)c->bi;
   psinfo = (pwdshadow_info *)on->on_bi.bi_private;
   rc     = ARG_BAD_CONF;

   assert ( c->type == PSHADOW_DEFAULT );
   Debug(LDAP_DEBUG_TRACE, "==> pshadow_cf_default\n" );

   switch ( c->op )
   {
      case SLAP_CONFIG_EMIT:
      Debug(LDAP_DEBUG_TRACE, "==> pshadow_cf_default emit\n" );
      rc = 0;
      if ( !BER_BVISEMPTY( &psinfo->def_policy ))
      {
         if ((rc = value_add_one( &c->rvalue_vals, &psinfo->def_policy )) != 0)
            return(rc);
         rc = value_add_one( &c->rvalue_nvals, &psinfo->def_policy );
      };
      break;

      case LDAP_MOD_DELETE:
      Debug(LDAP_DEBUG_TRACE, "==> pshadow_cf_default delete\n" );
      if ( psinfo->def_policy.bv_val )
      {
         ber_memfree ( psinfo->def_policy.bv_val );
         psinfo->def_policy.bv_val = NULL;
      };
      psinfo->def_policy.bv_len = 0;
      rc = 0;
      break;

      case SLAP_CONFIG_ADD:
      // fallthru to LDAP_MOD_ADD

      case LDAP_MOD_ADD:
      Debug(LDAP_DEBUG_TRACE, "==> pshadow_cf_default add\n" );
      if ( psinfo->def_policy.bv_val )
      {
         ber_memfree ( psinfo->def_policy.bv_val );
      };
      psinfo->def_policy = c->value_ndn;
      ber_memfree( c->value_dn.bv_val );
      BER_BVZERO( &c->value_dn );
      BER_BVZERO( &c->value_ndn );
      rc = 0;
      break;
      
      default:
      abort ();
   };

   return(rc);
}


int
pshadow_db_destroy(
        BackendDB *                     be,
        ConfigReply *                   cr )
{
   slap_overinst *   on;
   pwdshadow_info *  psinfo;

   on                   = (slap_overinst *) be->bd_info;
   psinfo               = on->on_bi.bi_private;
   on->on_bi.bi_private = NULL;

   free( psinfo->def_policy.bv_val );
   free( psinfo );

   if ((cr))
      return(0);

   return(0);
}


int
pshadow_db_init(
        BackendDB *                     be,
        ConfigReply *                   cr )
{
   slap_overinst *   on;
   pwdshadow_info *  psinfo;

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
   psinfo = on->on_bi.bi_private = ch_calloc( sizeof(pwdshadow_info), 1 );
   psinfo->genattr  = NULL;
   psinfo->override = 1;
   psinfo->realtime = 0;

   return(0);
}


int
pwdshadow_initialize( void )
{
   int i;
   int code;

   for(i = 0; ((pshadow_ats[i].def)); i++)
   {
      if ((code = register_at(pshadow_ats[i].def, pshadow_ats[i].ad, 0)) != 0)
      {
         Debug( LDAP_DEBUG_ANY, "pwdshadow_initialize: register_at failed\n" );
         return(code);
      };
      if ((is_at_no_user_mod((*pshadow_ats[i].ad)->ad_type)))
      {
         (*pshadow_ats[i].ad)->ad_type->sat_flags |= SLAP_AT_MANAGEABLE;
      };
   };

   for (i = 0; ((pshadow_ocs[i])); i++)
   {
      if ((code = register_oc( pshadow_ocs[i], NULL, 0 )) != 0)
      {
         Debug( LDAP_DEBUG_ANY, "pwdshadow_initialize: register_oc failed\n");
         return(code);
      };
   };

   if ((code = config_register_schema( pshadow_cfg_ats, pshadow_cfg_ocs )) != 0)
   {
      Debug( LDAP_DEBUG_ANY, "pwdshadow_initialize: config_register_schema failed\n");
      return(code);
   };

   pshadow.on_bi.bi_type               = "pshadow";
   pshadow.on_bi.bi_flags              = SLAPO_BFLAG_SINGLE;

   pshadow.on_bi.bi_db_init            = pshadow_db_init;
   //pshadow.on_bi.bi_db_open            = pshadow_db_open;
   //pshadow.on_bi.bi_db_close           = pshadow_db_close;
   pshadow.on_bi.bi_db_destroy         = pshadow_db_destroy;

   //pshadow.on_bi.bi_op_add             = pshadow_add;
   //pshadow.on_bi.bi_op_bind            = pshadow_bind;
   //pshadow.on_bi.bi_op_compare         = pshadow_compare;
   //pshadow.on_bi.bi_op_delete          = pshadow_restrict;
   //pshadow.on_bi.bi_op_modify          = pshadow_modify;
   //pshadow.on_bi.bi_op_search          = pshadow_search;

   //pshadow.on_bi.bi_connection_destroy = pshadow_connection_destroy;

   //pshadow.on_bi.bi_cf_ocs             = pshadow_cfg_ocs;

   return(overlay_register( &pshadow ));
}


/* end of source file */
