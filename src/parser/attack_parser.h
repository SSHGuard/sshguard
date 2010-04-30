
/* A Bison parser, made by GNU Bison 2.4.1.  */

/* Skeleton interface for Bison's Yacc-like parsers in C
   
      Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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
     LAST_LINE_REPEATED_N_TIMES = 264,
     SYSLOG_BANNER = 265,
     TIMESTAMP_SYSLOG = 266,
     TIMESTAMP_TAI64 = 267,
     AT_TIMESTAMP_TAI64 = 268,
     METALOG_BANNER = 269,
     SSH_INVALUSERPREF = 270,
     SSH_NOTALLOWEDPREF = 271,
     SSH_NOTALLOWEDSUFF = 272,
     SSH_LOGINERR_PREF = 273,
     SSH_LOGINERR_SUFF = 274,
     SSH_LOGINERR_PAM = 275,
     SSH_REVERSEMAP_PREF = 276,
     SSH_REVERSEMAP_SUFF = 277,
     SSH_NOIDENTIFSTR = 278,
     SSH_BADPROTOCOLIDENTIF = 279,
     DOVECOT_IMAP_LOGINERR_PREF = 280,
     DOVECOT_IMAP_LOGINERR_SUFF = 281,
     UWIMAP_LOGINERR = 282,
     CYRUSIMAP_SASL_LOGINERR_PREF = 283,
     CYRUSIMAP_SASL_LOGINERR_SUFF = 284,
     CUCIPOP_AUTHFAIL = 285,
     EXIM_ESMTP_AUTHFAIL_PREF = 286,
     EXIM_ESMTP_AUTHFAIL_SUFF = 287,
     SENDMAIL_RELAYDENIED_PREF = 288,
     SENDMAIL_RELAYDENIED_SUFF = 289,
     FREEBSDFTPD_LOGINERR_PREF = 290,
     FREEBSDFTPD_LOGINERR_SUFF = 291,
     PROFTPD_LOGINERR_PREF = 292,
     PROFTPD_LOGINERR_SUFF = 293,
     PUREFTPD_LOGINERR_PREF = 294,
     PUREFTPD_LOGINERR_SUFF = 295,
     VSFTPD_LOGINERR_PREF = 296,
     VSFTPD_LOGINERR_SUFF = 297
   };
#endif
/* Tokens.  */
#define IPv4 258
#define IPv6 259
#define HOSTADDR 260
#define WORD 261
#define INTEGER 262
#define SYSLOG_BANNER_PID 263
#define LAST_LINE_REPEATED_N_TIMES 264
#define SYSLOG_BANNER 265
#define TIMESTAMP_SYSLOG 266
#define TIMESTAMP_TAI64 267
#define AT_TIMESTAMP_TAI64 268
#define METALOG_BANNER 269
#define SSH_INVALUSERPREF 270
#define SSH_NOTALLOWEDPREF 271
#define SSH_NOTALLOWEDSUFF 272
#define SSH_LOGINERR_PREF 273
#define SSH_LOGINERR_SUFF 274
#define SSH_LOGINERR_PAM 275
#define SSH_REVERSEMAP_PREF 276
#define SSH_REVERSEMAP_SUFF 277
#define SSH_NOIDENTIFSTR 278
#define SSH_BADPROTOCOLIDENTIF 279
#define DOVECOT_IMAP_LOGINERR_PREF 280
#define DOVECOT_IMAP_LOGINERR_SUFF 281
#define UWIMAP_LOGINERR 282
#define CYRUSIMAP_SASL_LOGINERR_PREF 283
#define CYRUSIMAP_SASL_LOGINERR_SUFF 284
#define CUCIPOP_AUTHFAIL 285
#define EXIM_ESMTP_AUTHFAIL_PREF 286
#define EXIM_ESMTP_AUTHFAIL_SUFF 287
#define SENDMAIL_RELAYDENIED_PREF 288
#define SENDMAIL_RELAYDENIED_SUFF 289
#define FREEBSDFTPD_LOGINERR_PREF 290
#define FREEBSDFTPD_LOGINERR_SUFF 291
#define PROFTPD_LOGINERR_PREF 292
#define PROFTPD_LOGINERR_SUFF 293
#define PUREFTPD_LOGINERR_PREF 294
#define PUREFTPD_LOGINERR_SUFF 295
#define VSFTPD_LOGINERR_PREF 296
#define VSFTPD_LOGINERR_SUFF 297




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 1676 of yacc.c  */
#line 78 "attack_parser.y"

    char *str;
    int num;



/* Line 1676 of yacc.c  */
#line 143 "attack_parser.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE yylval;


