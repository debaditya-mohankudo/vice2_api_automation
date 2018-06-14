
# -*- coding: utf-8 -*-
"""
http://stackoverflow.com/questions/10406135
/unicodedecodeerror-ascii-codec-cant-decode-byte-0xd1-in-position-2-ordinal

OPENSSL documentation :
    https://www.openssl.org/docs/apps/req.html ( for utf8)
"""


import os
import time
import codecs
import subprocess

INTERNAL_ORG_DOMAIN = ('.bbtest.net',
                       '.symclab.net',
                       '.biznus.com',
                       '.netsure.biz',
                       '.netsure.info',
                       '.netsure.net',
                       '.netsure.us',
                       '.symclab.com',
                       '.symantec.com',
                       '.wssqa.net')



class GenCsr(object):
    __usage__ = '''
    Generates a csr based on the given parameters
    SET UP  :
        OPENSSL shall be installed and added to path and
        python shall be installed and added to path
        download python from here : version - 2.7.* for 32 bit
        http://www.python.org/ftp/python/2.7.6/python-2.7.6.msi

    USAGE :
        x1 = GenCsr()
        print x1.type_RSA(
            'abc.com','org','o','locality','state','IN',2048,'sha256')
        print x1.type_DSA(
            'abc.com','org','o','locality','state','IN',2048,'sha256')
        print x1.type_ECC(
            'abc.com','org','o','locality','state','IN',2048,'sha256')

    the private key and csr stored as /csr/cn.key and /csr/cn.csr
    __maintainer__ = 'debaditya_mohankudo@symantec.com'

    '''
    # support added for multiple sans in csr
    # added calls for rsa , dsa and ecc separately :
    # .type_RSA() ,.type_DSA(). type_ECC()
    # print commands made python 3 compatible
    # TODO: implement python2/3 compatibility for unicode strings

    def __init__(self, debug=True, save_key=True):
        if not os.path.isdir('csr'): os.mkdir('csr')
        dir_t = str(time.time()+time.perf_counter())
        fpath = os.path.join('.', 'csr')  # creates .\csr ( os wise)
        if not os.path.exists(fpath): os.mkdir(fpath)
        self.debug = debug
        self.save_key = save_key
        self.csr_path = os.path.join(fpath, 'cn.csr')
        self.pvtkey_path = os.path.join(fpath, 'cn.key')
        self.conf_path = os.path.join(fpath, 'cn.conf.txt')
        self.dsaparampath = os.path.join(fpath, 'dsaparam.pem')
        self.eccparampath = os.path.join(fpath, 'eccparam.pem')


    def print_log(self, message, debug=None):
        if debug is None:
            debug = self.debug

        if debug:
            print('{info}'.format(info=message))

    def _clean_old_files(self):
        for file in [self.csr_path,
                     self.conf_path,
                     self.pvtkey_path,
                     self.dsaparampath,
                     self.eccparampath]:
            if(os.path.isfile(file)):
                os.remove(file)

    def _gen_openssl_conf(self):
        f = codecs.open(self.conf_path, 'w', 'utf-8')
        #f = codecs.open(self.conf_path, 'w')
        #if str(self.Sig_Alg).upper()== 'DSA': self.hash_alg='sha256'
        f.write('[ req ]\
                {nl}default_bits={keysize}\
                {nl}prompt = no\
                {nl}encrypt_key = no\
                {nl}distinguished_name = dn\
                {nl}default_md={hash_alg}{nl}'.format(
                keysize=self.Key_Size,
                hash_alg=self.hash_alg,
                nl='\n'))
        #to add challenge password {nl}attributes=req_attributes{nl}
        sanincsrFlag = None
        if self.SanInCSR is not None and self.SanInCSR != []:
            f.write("req_extensions = req_ext{nl}".format(nl='\n'))
            sanincsrFlag = True
        # format - unicode
        # http://stackoverflow.com/questions/3235386
        #/python-using-format-on-a-unicode-escaped-string
        f.write('\n[dn]')
        if self.CN:
            f.write('\nCN ={cn}'.format(cn=self.CN))
        if self.O:
            f.write('\nO = {org}'.format(org=self.O))
        if self.OU:
            f.write('\n0.OU = {org_unit}'.format(org_unit=self.OU))
        if self.L:
            f.write('\nL = {locality}'.format(locality=self.L))
        if self.ST:
            f.write('\nST = {state}'.format(state=self.ST))
        if self.C:
            f.write('\nC = {country}'.format(country=self.C))
        f.write('\nemailAddress = debaditya_mohankudo@symantec.com')
        if sanincsrFlag:
            f.write('{nl}[req_ext]\
                     {nl}subjectAltName = @alt_names{nl}\
                     {nl}[alt_names]'.format(nl='\n'))

            for i, san in enumerate(self.SanInCSR):
                f.write('{nl}DNS.{count}= {san}'.format(
                    nl='\n', count=str(i+1), san=san))
        if False:  # https://www.openssl.org/docs/apps/req.html#COMMAND-OPTIONS
            f.write('\n[ req_attributes ]\nchallengePassword = P@ssword\n')
        f.close()

    def _gen_csr(self):
        self.csr = None
        self._clean_old_files()
        self._gen_openssl_conf()
        func_call_dict = {'DSA': self._gen_dsa_keypair,
                          'ECC': self._gen_ecc_keypair,
                          'RSA': self._gen_rsa_keypair,
                          }
        
        func_call_dict[self.Sig_Alg.upper()]()
        max_sleep = 10
        counter = 0
        while not os.path.isfile(self.pvtkey_path) and counter < max_sleep:
            time.sleep(.5)
            counter += .5


        self.print_log('slept ..', self.debug)
        csrGenCommand = 'openssl req -new -utf8 -key {keyfile} -out {csrfile} -config {configfile} '.format(
                        keyfile=self.pvtkey_path,
                        csrfile=self.csr_path,
                        configfile=self.conf_path)
        subprocess.call(csrGenCommand)
        self.print_log(csrGenCommand)
        counter = 0
        while not os.path.isfile(self.csr_path) and counter < max_sleep:
            time.sleep(.5)
            counter += .5



        self.print_log('{nl}csr saved in file :{nl} {csrfile}\
               {nl}private key saved in file :{nl} {keyfile}'.format(
                nl='\n',
                csrfile=os.path.abspath(self.csr_path),
                keyfile=os.path.abspath(self.pvtkey_path)))            
        self._read_csr_from_file()

    def _gen_dsa_keypair(self):
        newKeyParam = 'dsa:'+self.dsaparampath
        # Generate the Dsa Params for dsa ( p q and G)
        dsaParamGenCommand = "openssl  dsaparam " + self.Key_Size  + " -out " + self.dsaparampath # ( for dsa key size can be 2048 or 2048-256, like using subprimes)
        dsaPvtKeyGenCommand = "openssl gendsa  -out " +self.pvtkey_path + " " +self. dsaparampath
        self.print_log('dsa param\n{dsaParamGenCommand}\ndsa pvtkey\n{dsaPvtKeyGenCommand}\n'.format(
            dsaParamGenCommand=dsaParamGenCommand,
            dsaPvtKeyGenCommand=dsaPvtKeyGenCommand))
        subprocess.call(dsaParamGenCommand)
        subprocess.call(dsaPvtKeyGenCommand)

    def _gen_ecc_keypair(self):
        if str(self.Key_Size).isdigit():
            self.Key_Size = 'prime256v1'
        eccParamGenCommand = "openssl ecparam -name " + self.Key_Size + "  -genkey -out " + self.pvtkey_path
        self.print_log('EC Param Generation\n{}'.format(eccParamGenCommand))
        subprocess.call(eccParamGenCommand)

    def _gen_rsa_keypair(self):
        rsaPvtKeyGenCommand = "openssl genrsa -out " +self.pvtkey_path + " " + self.Key_Size 
        subprocess.call(rsaPvtKeyGenCommand)
        self.print_log('RSA Private Key Generation\n{}'.format(rsaPvtKeyGenCommand))

    def _read_csr_from_file(self):
        if os.path.exists(self.csr_path):
            with open(self.csr_path, 'r') as f:
                self.csr = f.read()
            return self.csr
        else:
            self.print_log('{}'.format('csr not created ................'))
            return False

    def get_csr(self, CN, O, OU, L, ST, C, Signing_Algorithm,
                keysize=2048, hash_alg='sha256', SanInCSR=[]):
        self.CN = CN
        self.SanInCSR = SanInCSR
        self.O = O
        self.OU = OU
        self.L = L
        self.ST = ST
        self.C = C
        self.Sig_Alg = Signing_Algorithm
        self.Key_Size = str(keysize)
        self.hash_alg = hash_alg
        if not self.internal_domain:
            print('{warning}'.format(warning='Your domain not in CAS approved Domain. Good to use from internal domains: \n'+ str(INTERNAL_ORG_DOMAIN) ))
        self._gen_csr()
        # comment the line below to save the pvt key file
        if not self.save_key:
            self.print_log('{info}'.format(info='Erasing pvt key file'), True)
            if os.path.isfile(self.pvtkey_path): os.remove(self.pvtkey_path)
        return self.csr

    def get_pvt_key(self):
        if self.save_key:
            if os.path.isfile(self.pvtkey_path):
                with open(self.pvtkey_path) as r:
                    return r.read()

    def type_RSA(self, CN, O, OU, L, ST, C,
                 keysize=2048,
                 hash_alg='sha256',
                 SanInCSR=[]):
        self.print_log('{}'.format('=' * 40))
        self.print_log('{}'.format('System call to generate a RSA csr'))
        self.print_log('{}'.format('=' * 40))
        return self.get_csr(CN, O, OU, L, ST, C, 'RSA',
                            keysize, hash_alg, SanInCSR)

    def type_DSA(self, CN, O, OU, L, ST, C,
                 keysize=2048,
                 hash_alg='sha256',
                 SanInCSR=[]):
        self.print_log('{}'.format('=' * 40))
        self.print_log('{}'.format('System call to generate a DSA csr'))
        self.print_log('{}'.format('=' * 40))
        return self.get_csr(CN, O, OU, L, ST, C,
                            'DSA', keysize, hash_alg, SanInCSR)

    def type_ECC(self, CN, O, OU, L, ST, C,
                 curve_name='prime256v1',
                 hash_alg='sha256',
                 SanInCSR=[]):
        # if you want to use a specific curve to use provide as keysize param
        self.print_log('{}'.format('=' * 40))
        self.print_log('{}'.format('System call to generate a ECC csr'))
        self.print_log('{}'.format('=' * 40))
        return self.get_csr(CN, O, OU, L, ST, C, 'ECC',
                            curve_name, hash_alg, SanInCSR)

    @property
    def fqdn(self):
        if '.' not in self.CN:
            return False
        elif self.CN.replace('.', '').isdigit():
            return False
        else:
            return True

    @property
    def internal_domain(self):
        status = []
        if self.CN:
            for domain in INTERNAL_ORG_DOMAIN:
                if not domain.lower() in self.CN.lower():
                    status.append(False)
                else:
                    status.append(True)
        if self.SanInCSR:
            for domain in INTERNAL_ORG_DOMAIN:
                for cn in self.SanInCSR:
                    if not domain.lower() in cn.lower():
                        status.append(False)
                    else:
                        status.append(True)

        if True in status:
            return True
        else:
            return False


if __name__ == "__main__":

    x1 = GenCsr() # DO NOT DELETE/COMMENT THIS
    # below section for generating individual csrs
    # generate a DSA csr
    #print(x1.type_DSA('仮名交じり文.testmssl1.com','testmssl1','OrganUnitFebWed05222657','locality','state','IN',2048,'sha1'))
    # generate an ECC csr
    print(x1.type_ECC('仮名交じり文.bbtest.net','Symantec Corporation','仮名交じり文','Mountain View','California','US',2048,'sha256', ['a.1','b.2']))
    # generate an RSA csr
    #print(x1.type_RSA('checkev2yct.bbtest.net','Symantec Corporation','','Mountain View','California','US',2048,'sha256'))

