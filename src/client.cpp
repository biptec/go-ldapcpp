#include "stdlib.h"
#include "client.h"

clientLogger *log = new clientLogger();

/*
  Active Directory class.

  client::bind can throw BindException on errors.
  all search functions can throw SearchException on errors.
  all modify functions can throw both SearchException and OperationalException on errors.
   text description will be in 'msg' property
   numeric code in 'code' property
*/

client::client() {
/*
  Constructor, to initialize default values of global variables.
*/
    ds = NULL;
}

client::~client() {
/*
  Destructor, to automaticaly free initial values allocated at bind().
*/
    close(ds);
    delLogger();
}

void client::close(LDAP *ds) {
    if (ds != NULL) {
        ldap_unbind_ext(ds, NULL, NULL);
    }
}

void client::bind(clientConnParams _params) {
    ldap_prefix = _params.use_ldaps ? "ldaps" : "ldap";

    if (!_params.uries.empty()) {
        for (vector <string>::iterator it = _params.uries.begin(); it != _params.uries.end(); ++it) {
            if (it->find("://") == string::npos) {
                _params.uri = ldap_prefix + "://" + *it;
            } else {
                _params.uri = *it;
            }
            try {
                bind(&ds, _params);
                params = _params;
                return;
            }
            catch (BindException&) {
                if (ds != NULL) {
                    ldap_unbind_ext(ds, NULL, NULL);
                    ds = NULL;
                }

                if (it != (_params.uries.end() - 1)) {
                    continue;
                } else {
                    throw;
                }
            }
        }
        throw BindException("No suitable connection uries found", PARAMS_ERROR);
    } else {
        throw BindException("No suitable connection params found", PARAMS_ERROR);
    }
}

void client::bind(vector <string> uries, string binddn, string bindpw, string search_base, bool secured) {
/*
  Wrapper around bind to support list of uries
*/
    clientConnParams _params;
    _params.uries = uries;
    _params.binddn = binddn;
    _params.bindpw = bindpw;
    _params.search_base = search_base;
    _params.secured = secured;
    bind(_params);
}

void client::bind(string _uri, string binddn, string bindpw, string search_base, bool secured) {
/*
  Wrapper around bind to fill LDAP* structure
*/
    clientConnParams _params;
    _params.uries.push_back(_uri);
    _params.binddn = binddn;
    _params.bindpw = bindpw;
    _params.search_base = search_base;
    _params.secured = secured;
    bind(_params);
}

void client::bind(LDAP **ds, clientConnParams& _params) {
/*
  To set various LDAP options and bind to LDAP server.
  It set private pointer to LDAP connection identifier - ds.
  It returns nothing if operation was successfull, throws BindException otherwise.
*/
    close(*ds);

    int result, version, bindresult = -1;

    string error_msg;

    if (_params.use_ldaps && _params.use_tls) {
        error_msg = "Error in passed params: use_ldaps and use_tls are mutually exclusive";
        throw BindException(error_msg, PARAMS_ERROR);
    }

#if defined OPENLDAP
    result = ldap_initialize(ds, _params.uri.c_str());
#elif defined SUNLDAP
    result = ldapssl_init(_params.uri.c_str(), LDAPS_PORT, 1);
#else
#error LDAP library required
#endif
    if (result != LDAP_SUCCESS) {
        error_msg = "Error in ldap_initialize to " + _params.uri + ": ";
        error_msg.append(ldap_err2string(result));
        throw BindException(error_msg, SERVER_CONNECT_FAILURE);
    }

    if (_params.nettimeout != -1) {
        struct timeval optTimeout;
        optTimeout.tv_usec = 0;
        optTimeout.tv_sec = _params.nettimeout;

        result = ldap_set_option(*ds, LDAP_OPT_TIMEOUT, &optTimeout);
        if (result != LDAP_OPT_SUCCESS) {
            error_msg = "Error in ldap_set_option (general timeout): ";
            error_msg.append(ldap_err2string(result));
            throw BindException(error_msg, SERVER_CONNECT_FAILURE);
        }

        result = ldap_set_option(*ds, LDAP_OPT_NETWORK_TIMEOUT, &optTimeout);
        if (result != LDAP_OPT_SUCCESS) {
            error_msg = "Error in ldap_set_option (network timeout): ";
            error_msg.append(ldap_err2string(result));
            throw BindException(error_msg, SERVER_CONNECT_FAILURE);
        }
    }

    if (_params.timelimit != -1) {
        result = ldap_set_option(*ds, LDAP_OPT_TIMELIMIT, &_params.timelimit);
        if (result != LDAP_OPT_SUCCESS) {
            error_msg = "Error in ldap_set_option (time limit): ";
            error_msg.append(ldap_err2string(result));
            throw BindException(error_msg, SERVER_CONNECT_FAILURE);
        }
    }

    version = LDAP_VERSION3;
    result = ldap_set_option(*ds, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (result != LDAP_OPT_SUCCESS) {
        error_msg = "Error in ldap_set_option (protocol->v3): ";
        error_msg.append(ldap_err2string(result));
        throw BindException(error_msg, SERVER_CONNECT_FAILURE);
    }

    result = ldap_set_option(*ds, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (result != LDAP_OPT_SUCCESS) {
        error_msg = "Error in ldap_set_option (referrals->off): ";
        error_msg.append(ldap_err2string(result));
        throw BindException(error_msg, SERVER_CONNECT_FAILURE);
    }

    if (_params.use_tls) {
        result = ldap_start_tls_s(*ds, NULL, NULL);
        if (result != LDAP_SUCCESS) {
            error_msg = "Error in ldap_start_tls_s: ";
            error_msg.append(ldap_err2string(result));
            throw BindException(error_msg, SERVER_CONNECT_FAILURE);
        }
        _params.bind_method = "StartTLS";
    } else {
        _params.bind_method = _params.use_ldaps ? "LDAPS" : "plain";
    }

    if (_params.secured) {
#ifdef KRB5
        if (_params.use_gssapi) {
            krb_struct krb_param;
            if (krb5_create_cache(_params.domain.c_str(), &krb_param, _params.krb5_ccache_name, _params.krb5_keytab_name) == 0) {
                _params.login_method = "GSSAPI";

                bindresult = sasl_bind_gssapi(*ds);
                if (bindresult == LDAP_SUCCESS) {
                    ldap_set_rebind_proc(*ds, sasl_rebind_gssapi, NULL);
                }

                krb5_cleanup(krb_param);
            } else {
                bindresult = -1;
            }
        } else {
#endif
            _params.login_method = "DIGEST-MD5";
            bindresult = sasl_bind_digest_md5(*ds, _params.binddn, _params.bindpw);
#ifdef KRB5
        }
#endif
    } else {
        _params.login_method = "SIMPLE";
        bindresult = sasl_bind_simple(*ds, _params.binddn, _params.bindpw);
    }

    if (bindresult != LDAP_SUCCESS) {
        error_msg = "Error while " + _params.login_method + " ldap binding to " + _params.uri + ": ";
        error_msg.append(ldap_err2string(bindresult));
        throw BindException(error_msg, SERVER_CONNECT_FAILURE);
    }
}

map < string, map < string, vector<string> > > client::search(string DN, int scope, string filter, const vector <string> &attributes) {
/*
  General search function.
  It returns map with users found with 'filter' with specified 'attributes'.
*/

    if (ds == NULL) throw SearchException("Failed to use LDAP connection handler", LDAP_CONNECTION_ERROR);

    int result, errcodep;

    char *attrs[50];
    int attrsonly = 0;

    string error_msg = "";

    ber_int_t       pagesize = 2;
    ber_int_t       totalcount;
    struct berval   *cookie = NULL;
    int             iscritical = 1;

    LDAPControl     *serverctrls[2] = { NULL, NULL };
    LDAPControl     *pagecontrol = NULL;
    LDAPControl     **returnedctrls = NULL;

    LDAPMessage *res = NULL;
    LDAPMessage *entry;

    char *dn;

    bool morepages;

    map < string, map < string, vector<string> > > search_result;

    if (attributes.size() > 50) throw SearchException("Cant return more than 50 attributes", PARAMS_ERROR);

    unsigned int i;
    for (i = 0; i < attributes.size(); ++i) {
        attrs[i] = strdup(attributes[i].c_str());
    }
    attrs[i] = NULL;

    replace(filter, "\\", "\\\\");

    do {
        result = ldap_create_page_control(ds, pagesize, cookie, iscritical, &pagecontrol);
        if (result != LDAP_SUCCESS) {
            error_msg = "Failed to create page control: ";
            error_msg.append(ldap_err2string(result));
            break;
        }
        serverctrls[0] = pagecontrol;

        /* Search for entries in the directory using the parmeters.       */
        result = ldap_search_ext_s(ds, DN.c_str(), scope, filter.c_str(), attrs, attrsonly, serverctrls, NULL, NULL, LDAP_NO_LIMIT, &res);
        if ((result != LDAP_SUCCESS) & (result != LDAP_PARTIAL_RESULTS)) {
            error_msg = "Error in paged ldap_search_ext_s: ";
            error_msg.append(ldap_err2string(result));
            break;
        }
        serverctrls[0] = NULL;
        ldap_control_free(pagecontrol);
        pagecontrol = NULL;

        int num_results = ldap_count_entries(ds, res);
        if (num_results == 0) {
            error_msg = filter + " not found";
            result = OBJECT_NOT_FOUND;
            break;
        }

        map < string, vector<string> > valuesmap;

        for ( entry = ldap_first_entry(ds, res);
              entry != NULL;
              entry = ldap_next_entry(ds, entry) ) {
            dn = ldap_get_dn(ds, entry);
            valuesmap = _getvalues(entry);
            search_result[dn] = valuesmap;
            ldap_memfree(dn);
        }

        /* Parse the results to retrieve the contols being returned.      */
        result = ldap_parse_result(ds, res, &errcodep, NULL, NULL, NULL, &returnedctrls, false);
        if (result != LDAP_SUCCESS) {
            error_msg = "Failed to parse result: ";
            error_msg.append(ldap_err2string(result));
            break;
        }

        /* Parse the page control returned to get the cookie and          */
        /* determine whether there are more pages.                        */
        pagecontrol = ldap_control_find(LDAP_CONTROL_PAGEDRESULTS, returnedctrls, NULL);
        if (pagecontrol == NULL) {
            error_msg = "Failed to find PAGEDRESULTS control";
            result = 255;
            break;
        }

        struct berval newcookie;
        result = ldap_parse_pageresponse_control(ds, pagecontrol, &totalcount, &newcookie);
        if (result != LDAP_SUCCESS) {
            error_msg = "Failed to parse pageresponse control: ";
            error_msg.append(ldap_err2string(result));
            break;
        }
        ber_bvfree(cookie);
        cookie = reinterpret_cast<berval*>(ber_memalloc( sizeof( struct berval ) ));
        if (cookie == NULL) {
            error_msg = "Failed to allocate memory for cookie";
            result = 255;
            break;
        }
        *cookie = newcookie;

        /* Cleanup the controls used. */
        ldap_controls_free(returnedctrls);
        returnedctrls = NULL;

        /* Determine if the cookie is not empty, indicating there are more pages for these search parameters. */
        if (cookie->bv_val != NULL && (strlen(cookie->bv_val) > 0)) {
            morepages = true;
        } else {
            morepages = false;
        }

        ldap_msgfree(res);
    } while (morepages);

    for (i = 0; i < attributes.size(); ++i) {
        free(attrs[i]);
    }

    if (cookie != NULL) {
        ber_bvfree(cookie);
    }

    if (error_msg.empty()) {
        return search_result;
    } else {
        ldap_msgfree(res);
        throw SearchException(error_msg, result);
    }
}

bool client::ifDNExists(string dn) {
/*
  Wrapper around two arguments ifDNExists for searching any objectclass DN
*/
    return ifDNExists(dn, "*");
}

bool client::ifDNExists(string dn, string objectclass) {
/*
  It returns true of false depends on object DN existence.
*/
    int result;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wwrite-strings"
    char *attrs[] = {"1.1", NULL};
#pragma GCC diagnostic pop
    LDAPMessage *res;
    string error_msg;
    int attrsonly = 1;

    if (ds == NULL) throw SearchException("Failed to use LDAP connection handler", LDAP_CONNECTION_ERROR);

    string filter = "(objectclass=" + objectclass + ")";
    result = ldap_search_ext_s(ds, dn.c_str(), LDAP_SCOPE_SUBTREE, filter.c_str(), attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
    ldap_msgfree(res);

    return (result == LDAP_SUCCESS);
}

vector <string> client::searchDN(string search_base, string filter, int scope) {
/*
  It returns vector with DNs found with 'filter'.
*/
    map < string, map < string, vector<string> > > search_result;

    vector <string> attributes;
    attributes.push_back("1.1");

    search_result = search(search_base.c_str(), scope, filter, attributes);

    vector <string> result;

    map < string, map < string, vector<string> > >::iterator res_it;
    for ( res_it=search_result.begin() ; res_it != search_result.end(); ++res_it ) {
        string dn = (*res_it).first;
        result.push_back(dn);
    }

    return result;
}


vector <string> client::search(string search_base, string filter, int scope, const vector <string> &attributes) {
/*
  It returns vector with DNs found with 'filter'.
*/
    map < string, map < string, vector<string> > > search_result;


    search_result = search(search_base.c_str(), scope, filter, attributes);

    vector <string> result;

    map < string, map < string, vector<string> > >::iterator res_it;
    for ( res_it=search_result.begin() ; res_it != search_result.end(); ++res_it ) {
        string dn = (*res_it).first;
        result.push_back(dn);
    }

    return result;
}

void client::modify(string dn, int mod_op, string attribute, vector <string> list) {
/*
  It performs an object modification operation (short_name/DN).
  It removes list from attribute.
  It returns nothing if operation was successfull, throw OperationalException - otherwise.
*/
    if (ds == NULL) throw SearchException("Failed to use LDAP connection handler", LDAP_CONNECTION_ERROR);

    LDAPMod *attrs[2];
    LDAPMod attr;
    int result;
    string error_msg;
    char** values = new char*[list.size() + 1];
    size_t i;

    for (i = 0; i < list.size(); ++i) {
        values[i] = new char[list[i].size() + 1];
        strcpy(values[i], list[i].c_str());
    }
    values[i] = NULL;

    attr.mod_op = mod_op;
    attr.mod_type = strdup(attribute.c_str());
    attr.mod_values = values;

    attrs[0] = &attr;
    attrs[1] = NULL;

    result = ldap_modify_ext_s(ds, dn.c_str(), attrs, NULL, NULL);
    if (result != LDAP_SUCCESS) {
        error_msg = "Error in modify '" + dn + "', ldap_modify_ext_s: ";
        error_msg.append(ldap_err2string(result));
        throw OperationalException(error_msg, result);
    }
    for (i = 0; i < list.size(); ++i) {
        delete[] values[i];
    }
    delete[] values;
    free(attr.mod_type);
}

void client::modifyDN(string dn, string newrdn, string newparent, int deleteoldrdn) {
    if (ds == NULL) throw SearchException("Failed to use LDAP connection handler", LDAP_CONNECTION_ERROR);

    int result = ldap_rename_s(ds, dn.c_str(), newrdn.c_str(), newparent.c_str(), deleteoldrdn, NULL, NULL);
    if (result != LDAP_SUCCESS){
        string error_msg = "Error in mod_rename, ldap_rename_s: ";
        error_msg.append(ldap_err2string(result));
        throw OperationalException(error_msg,result);
    }
}

void client::mod_add(string dn, string attribute, string value) {
/*
  It performs generic LDAP_MOD_ADD operation on object (short_name/DN).
  It adds value to attribute.
  It returns nothing if operation was successfull, throw OperationalException - otherwise.
*/
    if (ds == NULL) throw SearchException("Failed to use LDAP connection handler", LDAP_CONNECTION_ERROR);

    LDAPMod *attrs[2];
    LDAPMod attr;
    char *values[2];
    int result;
    string error_msg;

    values[0] = strdup(value.c_str());
    values[1] = NULL;

    attr.mod_op = LDAP_MOD_ADD;
    attr.mod_type = strdup(attribute.c_str());
    attr.mod_values = values;

    attrs[0] = &attr;
    attrs[1] = NULL;

    result = ldap_modify_ext_s(ds, dn.c_str(), attrs, NULL, NULL);
    free(values[0]);
    free(attr.mod_type);
    if (result != LDAP_SUCCESS) {
        error_msg = "Error in mod_add, ldap_modify_ext_s: ";
        error_msg.append(ldap_err2string(result));
        throw OperationalException(error_msg, result);
    }
}

void client::mod_delete(string dn, string attribute, string value) {
/*
  It performs generic LDAP_MOD_DELETE operation on object (short_name/DN).
  It removes value from attribute.
  It returns nothing if operation was successfull, throw OperationalException - otherwise.
*/
    if (ds == NULL) throw SearchException("Failed to use LDAP connection handler", LDAP_CONNECTION_ERROR);

    LDAPMod *attrs[2];
    LDAPMod attr;
    char *values[2];
    int result;
    string error_msg;

    if (value.empty()) {
        values[0] = NULL;
    } else {
        values[0] = strdup(value.c_str());
    }
    values[1] = NULL;

    attr.mod_op = LDAP_MOD_DELETE;
    attr.mod_type = strdup(attribute.c_str());
    attr.mod_values = values;

    attrs[0] = &attr;
    attrs[1] = NULL;

    result = ldap_modify_ext_s(ds, dn.c_str(), attrs, NULL, NULL);
    if (!value.empty()) {
        free(values[0]);
    }
    free(attr.mod_type);
    if (result != LDAP_SUCCESS) {
        error_msg = "Error in mod_delete, ldap_modify_ext_s: ";
        error_msg.append(ldap_err2string(result));
        throw OperationalException(error_msg, result);
    }
}

void client::mod_move(string dn, string new_container) {
    if (ds == NULL) throw SearchException("Failed to use LDAP connection handler", LDAP_CONNECTION_ERROR);

    if (!ifDNExists(new_container)) {
        string error_msg = "Error in mod_move, destination DN does not exists: ";
        error_msg.append(new_container);
        throw OperationalException(error_msg, PARAMS_ERROR);
    }

    std::pair<string, string> rdn = explode_dn(dn)[0];
    string newrdn = rdn.first + "=" + rdn.second;

    int result = ldap_rename_s(ds, dn.c_str(), newrdn.c_str(), new_container.c_str(), 1, NULL, NULL);
    if (result != LDAP_SUCCESS) {
        string error_msg = "Error in mod_move, ldap_rename_s: ";
        error_msg.append(ldap_err2string(result));
        throw OperationalException(error_msg, result);
    }
}

void client::mod_rename(string dn, string cn) {
    if (ds == NULL) throw SearchException("Failed to use LDAP connection handler", LDAP_CONNECTION_ERROR);

    string newrdn = "CN=" + cn;

    int result = ldap_rename_s(ds, dn.c_str(), newrdn.c_str(), NULL, 1, NULL, NULL);
    if (result != LDAP_SUCCESS){
        string error_msg = "Error in mod_rename, ldap_rename_s: ";
        error_msg.append(ldap_err2string(result));
        throw OperationalException(error_msg,result);
    }
}

void client::mod_replace(string dn, string attribute, vector <string> list) {
/*
  It performs generic LDAP_MOD_REPLACE operation on object (short_name/DN).
  It removes list from attribute.
  It returns nothing if operation was successfull, throw OperationalException - otherwise.
*/
    if (ds == NULL) throw SearchException("Failed to use LDAP connection handler", LDAP_CONNECTION_ERROR);

    LDAPMod *attrs[2];
    LDAPMod attr;
    int result;
    string error_msg;
    char** values = new char*[list.size() + 1];
    size_t i;

    for (i = 0; i < list.size(); ++i) {
        values[i] = new char[list[i].size() + 1];
        strcpy(values[i], list[i].c_str());
    }
    values[i] = NULL;

    attr.mod_op = LDAP_MOD_REPLACE;
    attr.mod_type = strdup(attribute.c_str());
    attr.mod_values = values;

    attrs[0] = &attr;
    attrs[1] = NULL;

    result = ldap_modify_ext_s(ds, dn.c_str(), attrs, NULL, NULL);
    if (result != LDAP_SUCCESS) {
        error_msg = "Error in mod_replace, ldap_modify_ext_s: ";
        error_msg.append(ldap_err2string(result));
        throw OperationalException(error_msg, result);
    }
    for (i = 0; i < list.size(); ++i) {
        delete[] values[i];
    }
    delete[] values;
    free(attr.mod_type);
}

void client::mod_replace(string object, string attribute, string value) {
/*
  It performs generic LDAP_MOD_REPLACE operation on object (short_name/DN).
  It removes value from attribute.
  It returns nothing if operation was successfull, throw OperationalException - otherwise.
*/
    vector<string> values;
    values.push_back(value);
    return mod_replace(object, attribute, values);
}

void client::DeleteDN(string dn) {
/*
  It deletes given DN.
  It returns nothing if operation was successfull, throw OperationalException - otherwise.
*/
    if (ds == NULL) throw SearchException("Failed to use LDAP connection handler", LDAP_CONNECTION_ERROR);

    int result = ldap_delete_ext_s(ds, dn.c_str(), NULL, NULL);

    if (result != LDAP_SUCCESS) {
        string error_msg = "Error in DeleteDN, ldap_delete_s: ";
        error_msg.append(ldap_err2string(result));
        throw OperationalException(error_msg, result);
    }
}

string client::dn2domain(string dn) {
    string domain = "";

    vector < std::pair<string, string> > dn_exploded = explode_dn(dn);

    vector < std::pair<string, string> >::iterator it;
    for (it = dn_exploded.begin(); it != dn_exploded.end(); ++it) {
        if (upper(it->first) == "DC") {
            domain += it->second;
            domain += ".";
        }
    }
    if (domain.size() > 0) {
        domain.erase(domain.size()-1, 1);
    }
    return domain;
}

string client::merge_dn(vector < std::pair<string, string> > dn_exploded) {
    std::stringstream result;

    vector < std::pair<string, string> >::iterator it;
    for (it = dn_exploded.begin(); it != dn_exploded.end(); ++it) {
        result << it->first;
        result << "=";
        result << it->second;
        if (it != dn_exploded.end() - 1) {
            result << ",";
        }
    }
    return result.str();
}

vector < std::pair<string, string> > client::explode_dn(string dn) {
#if defined OPENLDAP
#ifdef LDAP21
    LDAPDN *exp_dn;
#else
    LDAPDN exp_dn;
#endif
    int i;
    struct berval la_attr;
    struct berval la_value;
    vector < std::pair<string, string> > dn_exploded;

    int result = ldap_str2dn(dn.c_str(), &exp_dn, LDAP_DN_FORMAT_LDAPV3);

    if (result != LDAP_SUCCESS || exp_dn == NULL) {
        throw OperationalException("Wrong DN syntax", OU_SYNTAX_ERROR);
    }

    for (i = 0; exp_dn[i] != NULL; ++i) {
#ifdef LDAP21
        la_attr = (****exp_dn[i]).la_attr;
        la_value = (****exp_dn[i]).la_value;
#else
        la_attr = (**exp_dn[i]).la_attr;
        la_value = (**exp_dn[i]).la_value;
#endif
        dn_exploded.push_back( std::make_pair(la_attr.bv_val, la_value.bv_val) );
    }
    ldap_dnfree(exp_dn);
    return dn_exploded;
}
#elif defined SUNLDAP
    char** dns;
    char* pcDn = strdup(dn.c_str());
    dns = ldap_explode_dn(pcDn, 0);
    free(pcDn);

    char* next;
    unsigned int i = 0;
    vector < std::pair<string, string> > dn_exploded;

    while ((next = dns[i]) != NULL) {
        string temp(next);
        size_t pos = temp.find("=");
        if (pos != temp.npos) {
            string first = temp.substr(0, pos);
            string second = temp.substr(pos+1);
            dn_exploded.push_back( std::make_pair(first, second) );
        }
        i++;
    }
    ldap_value_free(dns);
    return dn_exploded;
}
#else
    throw OperationalException("Don't know how to do explode_dn", 255);
}
#endif


void client::RenameDN(string dn, string cn) {
    mod_rename(dn, cn);
}



vector <string> client::getObjectAttribute(string object, string attribute) {
/*
  It returns vector of strings with values for given attribute.
*/
    vector <string> attributes;
    attributes.push_back(attribute);

    map < string, vector<string> > attrs;
    attrs = getObjectAttributes(object, attributes);

    try {
        return attrs.at(attribute);
    }
    catch (const std::out_of_range&) {
        throw SearchException("No such attribute '" + attribute + "' in '" + object + "'", ATTRIBUTE_ENTRY_NOT_FOUND);
    }
}

map <string, vector <string> > client::getObjectAttributes(string object) {
/*
  It returns map of all object attributes.
*/
    vector <string> attributes;
    attributes.push_back("*");
    return getObjectAttributes(object, attributes);
}

map <string, vector <string> > client::getObjectAttributes(string dn, const vector<string> &attributes) {
/*
  It returns map of given object attributes.
*/
    map < string, map < string, vector<string> > > search_result;

    search_result = search(dn, LDAP_SCOPE_BASE, "(objectclass=*)", attributes);

    map < string, vector<string> > attrs;
    try {
        attrs = search_result.at(dn);
    }
    catch (const std::out_of_range&) {
        attrs = map < string, vector<string> >();
    }

    // on-fly convertion of objectSid from binary to string
    // not sure if it should be done here as end user could want to see actual binary data
    // and covert it only if it is required.
//    map < string, vector<string> >::iterator it = attrs.find("objectSid");
//    if (it != attrs.end()) {
//        vector<string> sid;
//        for (unsigned int i = 0; i < it->second.size(); ++i) {
//            sid.push_back( decodeSID(it->second[i]) );
//        }
//        it->second = sid;
//    }

    return attrs;
}

void client::MoveObject(string dn, string new_container) {
    mod_move(dn, new_container);
}



void client::clearObjectAttribute(string object, string attr) {
    mod_delete(object, attr, "");
}

void client::setObjectAttribute(string object, string attr, string value) {
    mod_replace(object, attr, value);
}

void client::setObjectAttribute(string object, string attr, vector <string> values) {
    mod_replace(object, attr, values);
}

/*
AD can set following limit (http://support.microsoft.com/kb/315071/en-us):
 MaxValRange - This value controls the number of values that are returned
   for an attribute of an object, independent of how many attributes that
   object has, or of how many objects were in the search result. If an
   attribute has more than the number of values that are specified by the
   MaxValRange value, you must use value range controls in LDAP to retrieve
   values that exceed the MaxValRange value. MaxValueRange controls the
   number of values that are returned on a single attribute on a single object.

OpenLDAP does not support ranged controls for values:
  https://www.mail-archive.com/openldap-its@openldap.org/msg00962.html

So the only way is it increase MaxValRange in DC:
 Ntdsutil.exe
   LDAP policies
     connections
       connect to server "DNS name of server"
       q
     Show Values
     Set MaxValRange to 10000
     Show Values
     Commit Changes
     Show Values
     q
   q
*/
map < string, vector<string> > client::_getvalues(LDAPMessage *entry) {
    if ((ds == NULL) || (entry == NULL)) throw SearchException("Failed to use LDAP connection handler", LDAP_CONNECTION_ERROR);

    map < string, vector<string> > result;

    BerElement *berptr;

    struct berval data;

    for ( char *next = ldap_first_attribute(ds, entry, &berptr);
          next != NULL;
          next = ldap_next_attribute(ds, entry, berptr) ) {
        vector <string> temp;
        struct berval **values = ldap_get_values_len(ds, entry, next);
        if (values == NULL) {
            string error = "Error in ldap_get_values_len for _getvalues: no values found";
            throw SearchException(error, ATTRIBUTE_ENTRY_NOT_FOUND);
        }
        for (unsigned int i = 0; values[i] != NULL; ++i) {
            data = *values[i];
            temp.push_back(string(data.bv_val, data.bv_len));
        }
        result[next] = temp;

        // cout << bin << " _getvalues['" << next << "'] = '" << vector2string(temp) << "'" << endl;
        ldap_memfree(next);
        ldap_value_free_len(values);
    }

    ber_free(berptr, 0);

    return result;
}


vector <string> client::DNsToShortNames(vector <string> &v) {
    vector <string> result;

    vector <string>::iterator it;
    for (it = v.begin(); it != v.end(); ++it) {
        vector <string> short_v;
        try {
            short_v = getObjectAttribute(*it, "sAMAccountName");
        }
        catch (SearchException& ex) {
            if (ex.code == ATTRIBUTE_ENTRY_NOT_FOUND ||
                // object could be not found if it is in a different search base / domain
                ex.code == OBJECT_NOT_FOUND) {
                result.push_back(*it);
                continue;
            }
            throw;
        }
        result.push_back(short_v[0]);
    }
    return result;
}

string client::domain2dn(string domain) {
    replace(domain, ".", ",DC=");
    return "DC=" + domain;
}

vector<string> client::get_ldap_servers(string domain, string site) {
    vector<string> servers;
    if (!site.empty()) {
        string srv_site = "_ldap._tcp." + site + "._sites." + domain;
        try {
            servers = perform_srv_query(srv_site);
        } catch (BindException &ex) { }
    }

    string srv_default = "_ldap._tcp." + domain;
    vector<string> servers_default = perform_srv_query(srv_default);

    // extend site DCs list with all DCs list (except already added site DCs) in case when site DCs is unavailable
    for (vector <string>::iterator it = servers_default.begin(); it != servers_default.end(); ++it) {
        if (find(servers.begin(), servers.end(), *it) == servers.end()) {
            servers.push_back(*it);
        }
    }

    return servers;
}



#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
// this magic was copy pasted and adopted from
// https://www.ccnx.org/releases/latest/doc/ccode/html/ccndc-srv_8c_source.html
vector<string> client::perform_srv_query(string srv_rec) {
    union dns_ans {
             HEADER header;
             unsigned char buf[NS_MAXMSG];
          } ans;
    size_t ans_size;

    char *srv_name = strdup(srv_rec.c_str());
    if (!srv_name) {
        throw BindException("Failed to allocate memory for srv_rec", LDAP_RESOLV_ERROR);
    }
    ans_size = res_search(srv_name, ns_c_in, ns_t_srv, ans.buf, sizeof(ans.buf));

    int qdcount, ancount;
    qdcount = ntohs(ans.header.qdcount);
    ancount = ntohs(ans.header.ancount);

    unsigned char *msg, *msgend;
    msg = ans.buf + sizeof(ans.header);
    msgend = ans.buf + ans_size;

    int size = 0, i;
    for (i = qdcount; i > 0; --i) {
        if ((size = dn_skipname(msg, msgend)) < 0) {
            free(srv_name);
            throw BindException("Error while resolving ldap server for " + srv_rec + ": dn_skipname < 0", LDAP_RESOLV_ERROR);
        }
        msg = msg + size + QFIXEDSZ;
    }

    int type = 0, priority = 0, weight = 0, port = 0, recclass = 0, ttl = 0;
    unsigned char *end;
    char host[NS_MAXDNAME];

    vector<string> ret;
    for (i = ancount; i > 0; --i) {
        size = dn_expand(ans.buf, msgend, msg, srv_name, strlen(srv_name)+1);
        if (size < 0) {
            free(srv_name);
            throw BindException("Error while resolving ldap server for " + srv_rec + ": dn_expand(srv_name) < 0", LDAP_RESOLV_ERROR);
        }
        msg = msg + size;

        GETSHORT(type, msg);
        GETSHORT(recclass, msg);
        GETLONG(ttl, msg);
        GETSHORT(size, msg);
        if ((end = msg + size) > msgend) {
            free(srv_name);
            throw BindException("Error while resolving ldap server for " + srv_rec + ": (msg + size) > msgend", LDAP_RESOLV_ERROR);
        }

        if (type != ns_t_srv) {
            msg = end;
            continue;
        }

        GETSHORT(priority, msg);
        GETSHORT(weight, msg);
        GETSHORT(port, msg);
        size = dn_expand(ans.buf, msgend, msg, host, sizeof(host));
        if (size < 0) {
            free(srv_name);
            throw BindException("Error while resolving ldap server for " + srv_rec + ": dn_expand(host) < 0", LDAP_RESOLV_ERROR);
        }
        // std::cout << priority << " " << weight << " " << ttl << " " << host << ":" << port << std::endl;
        ret.push_back(string(host));
        msg = end;
    }
    free(srv_name);
    return ret;
}
#pragma GCC diagnostic pop
