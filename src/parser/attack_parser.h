/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     IPv4 = 258,
     IPv6 = 259,
     HOSTADDR = 260,
     WORD = 261,
     INTEGER = 262,
     SYSLOG_BANNER_PID = 263,
     SYSLOG_BANNER = 264,
     TIMESTAMP_SYSLOG = 265,
     TIMESTAMP_TAI64 = 266,
     METALOG_BANNER = 267,
     SSH_INVALUSERPREF = 268,
     SSH_NOTALLOWEDPREF = 269,
     SSH_NOTALLOWEDSUFF = 270,
     SSH_LOGINERR_PREF = 271,
     SSH_LOGINERR_SUFF = 272,
     SSH_LOGINERR_PAM = 273,
     SSH_REVERSEMAP_PREF = 274,
     SSH_REVERSEMAP_SUFF = 275,
     SSH_NOIDENTIFSTR = 276,
     SSH_BADPROTOCOLIDENTIF = 277,
     DOVECOT_IMAP_LOGINERR_PREF = 278,
     DOVECOT_IMAP_LOGINERR_SUFF = 279,
     UWIMAP_LOGINERR = 280,
     CYRUSIMAP_SASL_LOGINERR_PREF = 281,
     CYRUSIMAP_SASL_LOGINERR_SUFF = 282,
     CUCIPOP_AUTHFAIL = 283,
     EXIM_ESMTP_AUTHFAIL_PREF = 284,
     EXIM_ESMTP_AUTHFAIL_SUFF = 285,
     SENDMAIL_RELAYDENIED_PREF = 286,
     SENDMAIL_RELAYDENIED_SUFF = 287,
     FREEBSDFTPD_LOGINERR_PREF = 288,
     FREEBSDFTPD_LOGINERR_SUFF = 289,
     PROFTPD_LOGINERR_PREF = 290,
     PROFTPD_LOGINERR_SUFF = 291,
     PUREFTPD_LOGINERR_PREF = 292,
     PUREFTPD_LOGINERR_SUFF = 293,
     VSFTPD_LOGINERR_PREF = 294,
     VSFTPD_LOGINERR_SUFF = 295
   };
#endif
/* Tokens.  */
#define IPv4 258
#define IPv6 259
#define HOSTADDR 260
#define WORD 261
#define INTEGER 262
#define SYSLOG_BANNER_PID 263
#define SYSLOG_BANNER 264
#define TIMESTAMP_SYSLOG 265
#define TIMESTAMP_TAI64 266
#define METALOG_BANNER 267
#define SSH_INVALUSERPREF 268
#define SSH_NOTALLOWEDPREF 269
#define SSH_NOTALLOWEDSUFF 270
#define SSH_LOGINERR_PREF 271
#define SSH_LOGINERR_SUFF 272
#define SSH_LOGINERR_PAM 273
#define SSH_REVERSEMAP_PREF 274
#define SSH_REVERSEMAP_SUFF 275
#define SSH_NOIDENTIFSTR 276
#define SSH_BADPROTOCOLIDENTIF 277
#define DOVECOT_IMAP_LOGINERR_PREF 278
#define DOVECOT_IMAP_LOGINERR_SUFF 279
#define UWIMAP_LOGINERR 280
#define CYRUSIMAP_SASL_LOGINERR_PREF 281
#define CYRUSIMAP_SASL_LOGINERR_SUFF 282
#define CUCIPOP_AUTHFAIL 283
#define EXIM_ESMTP_AUTHFAIL_PREF 284
#define EXIM_ESMTP_AUTHFAIL_SUFF 285
#define SENDMAIL_RELAYDENIED_PREF 286
#define SENDMAIL_RELAYDENIED_SUFF 287
#define FREEBSDFTPD_LOGINERR_PREF 288
#define FREEBSDFTPD_LOGINERR_SUFF 289
#define PROFTPD_LOGINERR_PREF 290
#define PROFTPD_LOGINERR_SUFF 291
#define PUREFTPD_LOGINERR_PREF 292
#define PUREFTPD_LOGINERR_SUFF 293
#define VSFTPD_LOGINERR_PREF 294
#define VSFTPD_LOGINERR_SUFF 295




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 27 "attack_parser.y"
{
    char *str;
    int num;
}
/* Line 1529 of yacc.c.  */
#line 134 "attack_parser.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

