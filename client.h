/*
   C++ Active Directory manipulation class.
   Based on adtool by Mike Dawson (http://gp2x.org/adtool/).
*/

#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <ldap.h>

#ifdef KRB5
#include <krb5.h>
#endif

#if defined( OPENLDAP )
    #define LDAPOPTSUCCESS LDAP_OPT_SUCCESS
#elif defined( SUNLDAP )
    #define LDAPOPTSUCCESS LDAP_SUCCESS
#endif

/*#include <mpatrol.h>*/
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <iostream>
#include <iterator>     // std::distance
#include <stdexcept>    // std::out_of_range
#include <algorithm>
#include <sys/time.h>
#include <limits>
#include <climits>
#include <cerrno>
#include <cstdlib>
#include <resolv.h>

// for OS X
#ifndef NS_MAXMSG
#define NS_MAXMSG 65535
#include <arpa/nameser_compat.h>
#endif

#define SUCCESS                      1
#define LDAP_CONNECTION_ERROR        2
#define PARAMS_ERROR                 4
#define SERVER_CONNECT_FAILURE       6
#define OBJECT_NOT_FOUND             8
#define ATTRIBUTE_ENTRY_NOT_FOUND    10
#define OU_SYNTAX_ERROR              12
#define LDAP_RESOLV_ERROR            14

#define MAX_PASSWORD_LENGTH 22

#define SCOPE_BASE         LDAP_SCOPE_BASE
#define SCOPE_BASEOBJECT   LDAP_SCOPE_BASEOBJECT
#define SCOPE_ONELEVEL     LDAP_SCOPE_ONELEVEL
#define SCOPE_ONE          LDAP_SCOPE_ONE
#define SCOPE_SUBTREE      LDAP_SCOPE_SUBTREE
#define SCOPE_SUB          LDAP_SCOPE_SUB
#define SCOPE_CHILDREN     LDAP_SCOPE_CHILDREN

#ifdef LDAP_SCOPE_SUBORDINATE
    #define SCOPE_SUBORDINATE LDAP_SCOPE_SUBORDINATE /* OpenLDAP extension */
    #define SCOPE_DEFAULT     LDAP_SCOPE_DEFAULT     /* OpenLDAP extension */
#else
    #define SCOPE_SUBORDINATE ((ber_int_t) 0x0003)
    #define SCOPE_DEFAULT     ((ber_int_t) -1)
#endif

using std::vector;
using std::map;
using std::string;
// using std::cout;
// using std::endl;

#ifdef KRB5
struct krb_struct {
    krb5_context context;
    char *mem_cache_env;
    krb5_ccache cc;
};
#endif

class Exception {
public:
      Exception(string _msg, int _code) { msg = _msg; code = _code; }
      int code;
      string msg;
};

class BindException: public Exception {
public:
      BindException(string _msg, int _code): Exception(_msg, _code) {}
};

class SearchException: public Exception {
public:
      SearchException(string _msg, int _code): Exception(_msg, _code) {}
};

class OperationalException: public Exception {
public:
      OperationalException(string _msg, int _code): Exception(_msg, _code) {}
};

struct connParams {
    public:
        string domain;
        string site;
        vector<string> uries;
        string binddn;
        string bindpw;
        string search_base;
        bool secured;
        bool use_gssapi;
        bool use_tls;
        bool use_ldaps;

        // LDAP_OPT_NETWORK_TIMEOUT, LDAP_OPT_TIMEOUT
        int nettimeout;
        // LDAP_OPT_TIMELIMIT
        int timelimit;

        connParams() :
            secured(true),
            use_gssapi(false),
            use_tls(false),
            use_ldaps(false),
            // by default do not touch timeouts
            nettimeout(-1), timelimit(-1)
        {};

        friend class client;

    private:
        string uri;
        string login_method;
        string bind_method;
};


class client {
public:
      client();
      ~client();

      static std::vector<string> get_ldap_servers(string domain, string site = "");
      static string domain2dn(string domain);

      void login(connParams _params);
      void login(string uri, string binddn, string bindpw, string search_base, bool secured = true);
      void login(std::vector <string> uries, string binddn, string bindpw, string search_base, bool secured = true);

      string binded_uri() { return params.uri; }
      string search_base() { return params.search_base; }
      string bind_method() { return params.bind_method; }
      string login_method() { return params.login_method; }

      void DeleteDN(string dn);
      void RenameDN(string object, string cn);
      void MoveObject(string object, string new_container);

      void setObjectAttribute(string object, string attr, string value);
      void setObjectAttribute(string object, string attr, vector <string> values);
      void clearObjectAttribute(string object, string attr);


      string          getObjectDN(string object);

      bool            ifDNExists(string object, string objectclass);
      bool            ifDNExists(string object);

      std::vector <string> getObjectAttribute(string object, string attribute);

      std::vector <string> searchNew(string search_base, string filter, int scope, const std::vector<string> &attributes);
      std::vector <string> searchDN(string search_base, string filter, int scope);
      std::map < string, std::map < string, std::vector<string> > > search(string OU, int scope, string filter, const std::vector <string> &attributes);

      std::map <string, std::vector <string> > getObjectAttributes(string object);
      std::map <string, std::vector <string> > getObjectAttributes(string object, const std::vector<string> &attributes);

private:
      connParams params;

      LDAP *ds;

      int isBinary(char * attrname);

      void login(LDAP **ds, connParams& _params);
      void logout(LDAP *ds);

      void mod_add(string object, string attribute, string value);
      void mod_delete(string object, string attribute, string value);
      void mod_rename(string object, string cn);
      void mod_replace(string object, string attribute, string value);
      void mod_replace(string object, string attribute, vector <string> list);
      void mod_move(string object, string new_container);
      std::map < string, std::vector<string> > _getvalues(LDAPMessage *entry);
      string dn2domain(string dn);
      vector < std::pair<string, string> > explode_dn(string dn);
      string merge_dn(vector < std::pair<string, string> > dn_exploded);
      std::vector <string> DNsToShortNames(std::vector <string> &v);

      std::string ldap_prefix;

      static std::vector<string> perform_srv_query(string srv_rec);
      static struct berval password2berval(string password);
};

inline string upper(string input) {
    std::transform(input.begin(), input.end(), input.begin(), ::toupper);
    return input;
}

inline string vector2string(const std::vector<string> &v, std::string separator = ", ") {
    std::stringstream ss;
    for(size_t i = 0; i < v.size(); ++i) {
        if (i != 0) ss << separator;
        ss << v[i];
    }
    return ss.str();
}

// ft is the number of 100-nanosecond intervals since January 1, 1601 (UTC)
inline time_t FileTimeToPOSIX(long long ft) {
    // never expired
    if (ft == 0) {
        ft = 9223372036854775807;
    }

    long long result;
    // Between Jan 1, 1601 and Jan 1, 1970 there are 11644473600 seconds
    // 100-nanoseconds = milliseconds * 10000 = seconds * 1000 * 10000
    result = ft - 11644473600 * 1000 * 10000;
    // convert back from 100-nanoseconds to seconds
    result = result / 10000000;
    if (result > std::numeric_limits<time_t>::max()) {
        return std::numeric_limits<time_t>::max();
    } else {
        return result;
    }
}

inline void replace(std::string& subject, const std::string& search,
                                   const std::string& replace) {
    size_t pos = 0;
    while((pos = subject.find(search, pos)) != std::string::npos) {
         subject.replace(pos, search.length(), replace);
         pos += replace.length();
    }
}

inline string itos(int num) {
    std::stringstream ss;
    ss << num;
    return(ss.str());
}

inline long long _stoll(string s) {
   errno = 0;
   char *endptr;
   int base = 10;
   long long val = strtoll(s.c_str(), &endptr, base);
   if ((errno == ERANGE && (val == LLONG_MAX || val == LLONG_MIN))
      || (errno != 0 && val == 0)) {
      throw std::invalid_argument("unacceptable input: " + s);
   }
   string end = string(endptr);
   if (end.size() != 0) {
      throw std::invalid_argument("invalid input: " + end);
   }
   return val;
}

inline string DecToBin(long long number) {
    if ( number == 0 ) return "0";
    if ( number == 1 ) return "1";

    if ( number % 2 == 0 )
        return DecToBin(number / 2) + "0";
    else
        return DecToBin(number / 2) + "1";
}

inline long long BinToDec(string number) {
    long long result = 0, pow = 1;
    for ( int i = number.length() - 1; i >= 0; --i, pow <<= 1 )
        result += (number[i] - '0') * pow;

    return result;
}

inline int ip2int(string ip) {
    string ipbin = "";
    std::istringstream iss(ip);
    string s;
    int iters = 0;
    while (getline(iss, s, '.')) {
        string bin = DecToBin(_stoll(s));
        if (bin.size() > 8) {
            throw std::invalid_argument("wrong ipv4 address: " + ip);
        } else if (bin.size() < 8) {
            while (bin.size() != 8) {
                bin = "0" + bin;
            }
        }
        ipbin = ipbin + bin;
        iters++;
    }
    if (iters != 4) {
        throw std::invalid_argument("wrong ipv4 address: " + ip);
    }
    long long ipdec = BinToDec(ipbin);
    if (ipdec > 2147483647) {
        ipdec = ipdec - 4294967296;
    }
    return ipdec;
}

inline string int2ip(string value) {
    long long intip = _stoll(value);
    if (intip < 0) {
        intip += 4294967296L;
    }
    string binip = DecToBin(intip);
    if (binip.size() > 32) {
        throw std::invalid_argument("wrong value: " + binip);
    } else if (binip.size() < 32) {
        while (binip.size() != 32) {
            binip = "0" + binip;
        }
    }
    string firstOctet = binip.substr(0, 8);
    string secondOctet = binip.substr(8, 8);
    string thirdOctet = binip.substr(16, 8);
    string fourthOctet = binip.substr(24, 8);
    string ip = itos(BinToDec(firstOctet)) + ".";
    ip += itos(BinToDec(secondOctet)) + ".";
    ip += itos(BinToDec(thirdOctet)) + ".";
    ip += itos(BinToDec(fourthOctet));
    return ip;
}

inline string decodeSID(string sid) {
/*
  It is taken from http://www.adamretter.org.uk/blog/entries/active-directory-ldap-users-primary-group.xml
*/
    std::stringstream result;
    result << "S-";

    // version
    result << int(sid[0]);

    // count of sub-authorities
    int countSubAuths = int(sid[1]) & 0xFF;

    result << "-";

    // get the authority
    long authority = 0;
    for (int i = 2; i <= 7; i++) {
        authority |= ((long)sid[i]) << (8 * (5 - (i - 2)));
    }
    result << authority;

    // iterate all the sub-auths
    int offset = 8;
    int size = 4; // 4 bytes for each sub auth
    for (int j = 0; j < countSubAuths; j++) {
        long subAuthority = 0;
        for (int k = 0; k < size; k++) {
            subAuthority |= (long)(sid[offset + k] & 0xFF) << (8 * k);
        }

        result << "-";
        result << subAuthority;

        offset += size;
    }

    return result.str();
}

void check_for_file_existence();

int sasl_bind_digest_md5(LDAP *ds, string binddn, string bindpw);
int sasl_bind_simple(LDAP *ds, string binddn, string bindpw);
#ifdef KRB5
int krb5_create_cache(const char *domain, krb_struct *krb_param);
void krb5_cleanup(krb_struct &krb_param);
int sasl_bind_gssapi(LDAP *ds);
int sasl_rebind_gssapi(LDAP * ld, LDAP_CONST char *url, ber_tag_t request, ber_int_t msgid, void *params);
#endif

#endif // _CLIENT_H_
