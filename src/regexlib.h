#ifndef REGEXLIB_H
#define REGEXLIB_H


/* an IPv4 address */
#define REGEXLIB_IPV4                   "((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)(\\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)){3})"

/* an IPv6 address, possibly compressed */
#define REGEXLIB_IPV6                   "(::|(([a-fA-F0-9]{1,4}):){7}(([a-fA-F0-9]{1,4}))|(:(:([a-fA-F0-9]{1,4})){1,6})|((([a-fA-F0-9]{1,4}):){1,6}:)|((([a-fA-F0-9]{1,4}):)(:([a-fA-F0-9]{1,4})){1,6})|((([a-fA-F0-9]{1,4}):){2}(:([a-fA-F0-9]{1,4})){1,5})|((([a-fA-F0-9]{1,4}):){3}(:([a-fA-F0-9]{1,4})){1,4})|((([a-fA-F0-9]{1,4}):){4}(:([a-fA-F0-9]{1,4})){1,3})|((([a-fA-F0-9]{1,4}):){5}(:([a-fA-F0-9]{1,4})){1,2}))"

/* an IPv4 address, mapped to IPv6 */
#define REGEXLIB_IPV4_MAPPED6           "(((0:){5}(0|[fF]{4})|:(:[fF]{4})?):{IPV4})"

/* a hostname, "localhost" or at least 2nd level */
#define REGEXLIB_HOSTNAME               "(localhost|([-a-zA-Z0-9]+\\.)+[a-zA-Z]+)"


#endif
