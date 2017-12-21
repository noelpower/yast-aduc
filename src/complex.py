#!/usr/bin/env python

import os.path, sys, traceback
from samba.net import Net
from samba.dcerpc import nbt
import uuid
import re
from subprocess import Popen, PIPE
from syslog import syslog, LOG_INFO, LOG_ERR, LOG_DEBUG, LOG_EMERG, LOG_ALERT
from ldap3 import Server, Connection, Tls, SASL, KERBEROS, ALL, SUBTREE,  ALL_ATTRIBUTES, MODIFY_REPLACE, MODIFY_ADD, ObjectDef, Reader, Writer

def modlist(in_mod_attrs):
    out_mod_attrs = {}
    for key in in_mod_attrs:
        out_mod_attrs[key] = (MODIFY_REPLACE, in_mod_attrs[key])
    return out_mod_attrs

def addlist(in_add_attrs):
    out_add_attrs = {}
    for key in in_add_attrs:
        out_add_attrs[key] = (MODIFY_ADD, in_add_attrs[key])
    return out_add_attrs

# the existing code expects the results in the format the python-ldap module
# would use to come back. Results are represented as a list of tuples where
# each tuple (for each entry in the results)
# contains 2 elements, #1 a string(dn) and #2 a dict (attributes)
#    where the dictionary of attributes is in a 'raw' form e.g. all
#    attribute values are lists of values where each value is a string
#    representation of the value. ldap3 has a more sophisticated representation.
#    For the moment lets just present things how the old code would see it
#    we can rewrite it later to use the ldap3 way of doing things (assuming
#    it works as we expect sasl etc.)
def mod_ldapify_result(conn):
    result = []
    if conn.result['result'] == 0 and len(conn.response) and len(conn.response[0]['attributes']):
        for entry in conn.response:
            dn = entry['dn']
            attrs = {}
            for key in entry['raw_attributes'].keys():
                new_attrs_list = []
                for val in entry['raw_attributes'][key]:
                    #print ("entry[%d][%s] has value type %s with %s"%(i, key, type(val), val))

                    try:
                        new_attrs_list.append(val.decode())
                    except:
                        #print("failed to decode %s, leaving it as bytes"%val)
                        new_attrs_list.append(val)
                    #print ("new_value = %s"%new_attrs_list[-1])
                attrs[key] = new_attrs_list
            result.append(tuple([dn, attrs]))
    else:
        return None
    return result

class ADUCConnection:
    def __init__(self, lp, creds):
        self.lp = lp
        self.creds = creds
        self.realm = lp.get('realm')
        net = Net(creds=creds, lp=lp)
        cldap_ret = net.finddc(domain=self.realm, flags=(nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS))
        username = '%s@%s' % (self.creds.get_username(), self.realm) if not self.realm in self.creds.get_username() else self.creds.get_username()
        if self.__kinit_for_gssapi():
            import ssl
            self.server = Server(cldap_ret.pdc_dns_name)
            self.conn = Connection(self.server, user = username, authentication=SASL, sasl_mechanism=KERBEROS)
        else:
            # #FIXME I think this should be removed in a production system
            # and we should just error out, otherwise we are transmitting
            # passwords in cleartext 
            self.server = Server(cldap_ret.pdc_dns_name)
            self.conn = Connection(self.server, user = username, password = self.creds.get_password())
        self.conn.bind()

    def __kinit_for_gssapi(self):
        p = Popen(['kinit', '%s@%s' % (self.creds.get_username(), self.realm) if not self.realm in self.creds.get_username() else self.creds.get_username()], stdin=PIPE, stdout=PIPE)
        p.stdin.write(('%s\n'%self.creds.get_password()).encode())
        p.stdin.flush()
        return p.wait() == 0

    def realm_to_dn(self, realm):
        return ','.join(['DC=%s' % part for part in realm.lower().split('.')])

    def __well_known_container(self, container):
        if container == 'system':
            wkguiduc = 'AB1D30F3768811D1ADED00C04FD8D5CD'
        elif container == 'computers':
            wkguiduc = 'AA312825768811D1ADED00C04FD8D5CD'
        elif container == 'dcs':
            wkguiduc = 'A361B2FFFFD211D1AA4B00C04FD7D83A'
        elif container == 'users':
            wkguiduc = 'A9D1CA15768811D1ADED00C04FD8D5CD'
        self.conn.search('<WKGUID=%s,%s>' % (wkguiduc, self.realm_to_dn(self.realm)), '(objectClass=container)', SUBTREE, attributes = ['distinguishedName'])

        result = mod_ldapify_result(self.conn)
        if result and len(result) > 0 and len(result[0]) > 1 and 'distinguishedName' in result[0][1] and len(result[0][1]['distinguishedName']) > 0:
            return result[0][1]['distinguishedName'][-1]

    def user_group_list(self):
        self.conn.search(self.__well_known_container('users'),  '(objectCategory=person)', SUBTREE, attributes = ALL_ATTRIBUTES)
        res1 = mod_ldapify_result(self.conn)
        self.conn.search(self.__well_known_container('users'), '(objectCategory=group)', SUBTREE, attributes = ALL_ATTRIBUTES)
        res2 = mod_ldapify_result(self.conn)
        return res1 + res2

    def computer_list(self):
        self.conn.search(self.__well_known_container('computers'),  '(objectCategory=computer)', SUBTREE, attributes = ALL_ATTRIBUTES)
        return mod_ldapify_result(self.conn)

    def update(self, dn, orig_map, modattr, addattr):
        result = True
        try:
            if len(modattr):
                oldattr = {}
                for key in modattr:
                    oldattr[key] = orig_map.get(key, [])
                print ('##### attempting mod %s'%modattr)
                self.conn.modify(dn, modlist(modattr))
                print ('##### appeared to work mod %s with %s'%(dn,modattr))
                result = (self.conn.result['result'] == 0)
            if len(addattr):
                print ('##### attempting add %s'%addattr)
                self.conn.modify(dn, addlist(addattr))
                print ('##### appeared to work add %s with %s'%(dn,addattr))
                result = (self.conn.result['result'] == 0)
        except Exception as e:
            print ('##### exception %s'%e)
            result = False
        return result

    def add_new_user(self, attrs):
        result = True
        basedn = self.__well_known_container('users')
        dn = 'CN=%s,%s' % (attrs['displayName'], basedn)
        print('adding new user for dn %s'%dn)
        obj_user = ObjectDef('user', self.conn)
        obj_user += 'sAMAccountName'
        r = Reader(self.conn, obj_user, basedn)
        w = Writer.from_cursor(r)
        w.new(dn)
        for key in attrs:
            w[0][key] = attrs[key]
        result = w[0].entry_commit_changes() 
        return result

    def delete_user(self, dn):
        result = False
        basedn = self.__well_known_container('users')
        obj_user = ObjectDef('user', self.conn)
        query = '(distinguishedName=%s)' % dn
        r = Reader(self.conn, obj_user, basedn, query)
        r.search()
        if len(r) == 1:
            w = Writer.from_cursor(r)
            w[0].entry_delete()
            result = w[0].entry_commit_changes() 
        return result
