# -*- coding: utf-8 -*-
'''
This module is to test vice2 apis and vice1 apis

~~~
1. using testdata from a python dictionary ( mostly for debug)
    testdata_dictionary contains all key value pairs required for api

    from mssl_api_testing import API
    test = API(env, testdata_dictionary)

    test.VICE2enroll()
    test.VICE2renew()
AND
    test.VICE1Enrollment()
    test.VICE1Renewal()

Features:
    if 'cn' value has __random__ it ll be replaced by a random value
    This random value ll be retained all along the life cycle of the cert
~~~
'''

# standard lib imports
import time
import pickle
import os
import re
import traceback
import sys
import socket
import pprint
import xml.dom.minidom
# 3rd party lib # to be installed using easy_install OR pip
import certifi
import requests  # dont use session objects for api call, not req and causes issues due to session polling not handled by servers
import socks

from requests.exceptions import ConnectionError
import codecs
requests.packages.urllib3.disable_warnings()  # supress https warnings

# user developed lib imports
from msslLib.GenCsr import GenCsr
from msslLib.GenUtils import Utils
############### Env details ##################
curr_dir = os.path.dirname(__file__)

##########################################
ENV = {}
debug = True
##########################################
ENV['ft'] = {
             'cert_jurisdiction_hash': '871557fbb9a6347c0870935ee572a6e7'

             }

ENV['pv'] = {
             'cert_jurisdiction_hash': '871557fbb9a6347c0870935ee572a6e7'
             }
ENV['ptnr'] = {
               'cert_jurisdiction_hash': '1a52ca0321a5ce5c67e4340313595262'}

ENV['pilot'] = {
                'cert_jurisdiction_hash': '6968dca973b5b6214e695b70a3fee6fe'}

# DR testing use browser: this python process does not use proxy
ENV['prod'] = {
               'cert_jurisdiction_hash': 'cdd8cfab30cfb4f939cd486cb9cf7607'}

######################################################

# tuples are immumatable lists and good search performance
# GLOBAL CONST VARIABLES IN CAPS and type : tuple ( dont want to mess with these)
#https://ft-certmanager-webservices.websecurity.symclab.net/vswebservices/rest/services/getAccountSetup?designation=AutoApprovalFlag
_VICE2_API_SET_ = ('enroll', 'renew', 'replace', 'getAlternate', 'pickup',
                   'gettokencounts', 'getVettedOrgsAndDomains',
                   'getEnrollmentFields', 'approve', 'reject',
                   'resetChallengePhrase', 'getAccountSetup',
                   'revoke', 'deactivate', 'updateSubscriberContact')

_VICE1_API_SET_ = ('Enrollment', 'Renewal', 'Pickup')

_CSR_PARAMS_ = ('cn', 'org', 'ou', 'locality', 'state', 'alg',
                'country', 'keysize', 'hash_alg', 'san_in_csr')


_METADATA_ = ('ExpectedResponse', 'tc_name')

_FORMATTER =  '\n{dash}\n'.format(dash='-' * 80)
# NEED USER AGENT TO FAKE AS BROWSER
USER_AGENT = {
'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
'Accept-Encoding': 'gzip, deflate, sdch',
'Accept-Language':'en-US,en;q=0.8',
'Connection':'keep-alive',
'Upgrade-Insecure-Requests':'1',
'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36'}





class doAPI(object):
    """
        Provides APIs to test vice1 and vice 2 operations
        ~~~

        @param:env dictionary object,
        @param: dictionary object with user input

        __maintainer__ = 'debaditya_mohankudo@symantec.com'
        last major update :added resetChallengePhrase
        __date__ = '17th Oct 2015'
        ~~~
    """
    def cprint(self, *args):
        if self.debug:
            print(*args)

    def __init__(self, env, user_data=None, EAClientJurHash=None, socks_proxy=None, debug=True):
        # cprint current time
        self.env = env
        self.__vice2BaseURL = None
        self.socks_proxy = socks_proxy
        self.__EAClientJurHash = EAClientJurHash # dont manipulate this value in runtime
        # this is associated with authentication of session
        self.user_data = dict(user_data) # dont mess with existing references

        #: this is introduced because of CICAPI class
        self._api = None
        self.temp_data = dict()
        self.debug = debug
        self.cprint('START::', time.ctime(time.time()))

    @property
    def EAClientJurHash(self):
        if self.__EAClientJurHash:
            self.cprint('Target mSSL account: ', self.__EAClientJurHash)
        return self.__EAClientJurHash

    @EAClientJurHash.setter
    def EAClientJurHash(self, value):
        self.__EAClientJurHash = value
        self.cprint('Target Account is set: ', value)

    @property
    def pem_file_name(self):
        return self.__pem_file_name

    @pem_file_name.setter
    def pem_file_name(self, value):
        self.__pem_file_name = value

    @property
    def vice2BaseURL(self):
        temp = {'ft': 'ft-certmanager-webservices.websecurity.symclab.net',
                 'pv': 'pv-certmanager-webservices.websecurity.symclab.net',
                 'pilot': 'pilot-certmanager-webservices.websecurity.symantec.com',
                 'prod': 'certmanager-webservices.websecurity.symantec.com'}
        if not self.__vice2BaseURL:
            self.__vice2BaseURL = temp.get(self.env, 'wrong env')
        return self.__vice2BaseURL

    @vice2BaseURL.setter 
    def vice2BaseURL(self, value):
        self.__vice2BaseURL = value

    def initialize_required_data(self):
        ''' initilises post data, and other input values '''

        self.__set_connection_params()




        self.post_data = dict(self.initialize_postdata_dict) # sets it blank

        #if not hasattr(self, 'csr_dict') or self.is_new_enrollment:
        #self.csr_dict = dict() # initilize ONLY once per execution/lifecycle

    def __set_log_file(self, outputfile=None, dirname=None):
        '''
            ~~~
            creates the desired log folder and
            crates a blank log filename
            this is only used when tc_file is given
            this runs once for debuggin
            and as many file calls for suite automation
            ~~~
        '''
        timestamp = str(time.ctime()).replace(' ', '-').replace(':', '-')
        outputfile, dirname = None, None

        if True:
            outputfile = '{time}_log.txt'.format(time=timestamp)
            dirname = '{dir_output}'.format(dir_output='vice2logs')

        if not os.path.isdir(dirname):
            os.mkdir(dirname)

        outputfilePath = os.path.join(dirname, outputfile)

        if not os.path.isfile(outputfilePath):
            with open(outputfilePath, 'w') as w:
                w.close()

        return outputfilePath

    def _serialize_data(self, data_object, pickle_file):
        with open(pickle_file, 'wb') as f:  # hard coded pickle name??
            pickle.dump(data_object, f)

    def _deserialize_pickle(self, data_object, pickle_file):
        with open(pickle_file, 'rb') as f:
            data_object = pickle.load(f)


    def _set_common_name(self):
        ''' sets the common name depending on the value,
            ___random__.bbtest.net -> __random__ gets replaced by a random value
            only for enroll/Enrollment api calls and serialized(pickle) to  file
            For renew/replace calls ->  this CN  is fetched from pickle file
            ( preserves state for later execution)
        '''
        word_length = 8
        #cn_pickle = 'random_cn.pickle'
        if self.is_new_enrollment:
            if '__random__' in self.user_data['cn']:
                # or self.is_random_cn.pickle :
                self.csr_dict['cn'] = self.user_data['cn'].replace(
                                                       '__random__',
                                    Utils().random_word(word_length))

                self.temp_data['cn'] = self.csr_dict['cn']
                self._serialize_data(self.temp_data, 'temp.pickle')

            else:
                self.csr_dict['cn'] = self.user_data['cn']
                # dont change the cn value, this line is only for clarity
        else:  # dont generate random for renew/replace/getAlternate- get from memory/pickle
            if '__random__' in self.user_data['cn']:
                self._deserialize_pickle(self.temp_data, 'temp.pickle')
                self.csr_dict['cn'] = self.temp_data['cn']
            else:
                self.csr_dict['cn'] = self.user_data['cn']

    def _copy_csr_parameter_from_test_data(self):
        ''' copy csr params from the test data to a new dictionary '''

        if not hasattr(self, 'csr_dict') or self.is_new_enrollment:
            self.csr_dict = dict() # initilize ONLY once per execution/lifecycle

        for param in _CSR_PARAMS_:
            self.csr_dict[param] = self.user_data.get(param, None)

        self.csr_dict['org'] = self.org
        #: over ride the value - guess from signature algorithm
        if not self.user_data['signatureAlgorithm']:
            self.csr_dict['alg'] = self.user_data['alg']
        else:
            self.csr_dict['alg'] = self.get_encryption_type(self.user_data['signatureAlgorithm'])

        #self.cprint(self.csr_dict['alg'])
        self._set_common_name()
        if self.debug: pprint.pprint(self.csr_dict)

    def _gen_csr(self):
        '''
            ~~~
            Generates CSR
            if __oldcsr__ in cn name get the old csr generated
            if __random__ in cn it creates and random word for it(only for enrolls)
            ~~~
        '''
        #: oldcsr value is needed
        if self.user_data.get('csr', None) is None:
            self._copy_csr_parameter_from_test_data()

            csr_obj = GenCsr()
            # deprecated
            if '__oldcsr__' in self.csr_dict['cn']:
                self.cprint('-' * 40)
                self.cprint('Reading Old CSR')
                self.cprint('-' * 40)

                self.post_data['csr'] = csr_obj._read_csr_from_file()  # read old csr
            else:
                self.cprint('-' * 40)
                self.cprint('Generating New CSR ...')
                self.cprint('-' * 40)

                self.post_data['csr'] = csr_obj.get_csr(self.csr_dict['cn'],
                        self.csr_dict['org'], self.csr_dict['ou'],
                        self.csr_dict['locality'], self.csr_dict['state'],
                        self.csr_dict['country'], self.csr_dict['alg'],
                        self.csr_dict['keysize'], self.csr_dict['hash_alg'],
                        self.csr_dict['san_in_csr'])

            if self.post_data['csr']:
                self.cprint('csr:{csr}'.format(csr=self.post_data['csr'][:200]))
        else:  #: api that does not req csr
            self.post_data['csr'] = self.user_data['csr']



    def __set_vice1_data(self):
        ''' sets the request_type and cert_jurisdiction_hash values
            removes signatureAlgorithm and specificEndDate
        '''
        if self.is_vice1:
            self.post_data['request_type'] = self.api
            self.post_data['cert_jurisdiction_hash'] = self.env.get('cert_jurisdiction_hash', None)
            #: signatureAlgorithm not supported in vice1
            if 'signatureAlgorithm' in self.post_data:
                self.post_data.pop('signatureAlgorithm')

            if 'specificEndDate' in self.post_data:
                self.post_data.pop('specificEndDate')

    def _prepare_post_data(self):
        ''' add user data to post data'''
        #: remove parameters required to gen csr now  shall be in this function
        if True: # only for enroll, renew, replace, alternate
            for item in set(self.user_data.keys()) - set(_CSR_PARAMS_) - set(_METADATA_):
                    self.post_data[item] = self.user_data[item]
            if 'comment' in self.post_data:
                self.post_data['comment'] += ' ' + str(self.host_ip) + '  ' + str(time.ctime(time.time()))
            else:
                self.post_data['comment'] = ' ' + str(self.host_ip) + ' ' + str(time.ctime(time.time()))
            self.__set_vice1_data()  # this is here because to remove signatureAlgorithm

    def __set_connection_params(self):
        ''' creates session object for the post request'''

        if self.EAClientJurHash:
            #self.pfx_file_name = self.env.get('cic_pfx_file', None)
            #self.__pem_file_name = self.pfx_file_name.replace('pfx', 'pem')
            pass
        self.cprint('Client cert used is: ', self.pem_file_name)

        if self.socks_proxy:
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', int(self.socks_proxy))
            socket.socket = socks.socksocket

        self.host_ip = ''
        if self.is_vice2:
            self.host_ip = socket.gethostbyname(self.vice2BaseURL)
        if self.is_vice1:
            self.host_ip = socket.gethostbyname(self.env['vice1'])
        
            

        # also to use GET
        if self.vice2BaseURL.startswith('certmanager'):
            self.verify = False
        else:
            self.verify = False #os.path.join(os.path.dirname(__file__), 'cacert.pem')

        USER_AGENT['Host'] = self.vice2BaseURL
        if self.is_vice2:
            self.testpage = 'https://' + self.vice2BaseURL + '/vswebservices/operations.htm'
      
            r = requests.post(self.testpage,
                cert=self.pem_file_name,
                headers=USER_AGENT,
                verify=self.verify)

            if r.status_code == requests.codes.ok:
                self.cprint('SSL connection successful to testpage: ' + self.testpage + '\n')
                self.cprint('actual host ip:: ' + self.host_ip)


    def __post_webservice_request(self):
        ''' post data for the api request
            gets the respone, prpares the report
            saves tran_id for next operation if required '''

        self.cprint(_FORMATTER)
        self.cprint('POST @::', time.ctime(time.time()))
        self.cprint('{f}post url:{f}{posturl}{f}'.format(
               f=_FORMATTER,
               posturl=self.post_url))
        self.cprint('Client cert used:', self.pem_file_name)
        if self.is_vice2:
            if True:
                self.response = requests.post(
                                self.post_url,
                                data=self.post_data,
                                cert=self.pem_file_name,
                                headers=USER_AGENT,
                                verify=self.verify) #certifi.where())
                #https://ixa.io/2015/04/22/using-an-ssl-intermediate-as-your-ca-cert-with-python-requests/

            else:
                self.cprint('post data not ready')
        else:
            self.response = requests.post(
                                self.post_url,
                                data=self.post_data,
                                verify=False)
        '''except ConnectionError:
            cprint '{err_msg}\n{f}'.format(
                err_msg='ConnectionError, check network setting',
                f=_FORMATTER)'''

        if hasattr(self, 'response'):
            self.cprint(self.response)

            if self.is_vice2 and self.response.status_code == requests.codes.ok:
                xml_resp = xml.dom.minidom.parseString(self.response.text)
                self.pretty_xml = xml_resp.toprettyxml()
            elif self.is_vice1:
                self.pretty_xml = self.response.text
            else:
                self.cprint(self.response.text)
            #for no debug
            if not self.debug: print(self.pretty_xml[:300])

            self.__vice_save_resp_status_as_dict()  # convert xml to dict object
            self.__verify_resp_prepare_report()
        else:
            self.response = ''

    def __vice_save_resp_status_as_dict(self):
        '''
        ~ Uses regular expressions to extract and return the
          parameters from the xml response  as a dictionary
        ~ dumps teh dictionary as pickle file
        ~ if the api call is Enroll then saves teh transaction_id and orderNumber
          as instance variables
        '''
        self.api_response_dict = dict()
        if self.is_vice2:
            for xml_tag in ('StatusCode',
                            'Transaction_ID',
                            'Message',
                            'Certificate',
                            'Error',
                            ):
                self.__search_pattern_add_to_status_dict('<{s}>(.*?)</{s}>'.format(s=xml_tag), self.pretty_xml, xml_tag)

        elif self.is_vice1:
            self.__search_pattern_add_to_status_dict('code=(.*?)&', self.pretty_xml, 'StatusCode')
            self.__search_pattern_add_to_status_dict('id=(.*?)&', self.pretty_xml, 'Transaction_ID')
            self.__search_pattern_add_to_status_dict('&status=(.*?)&', self.pretty_xml, 'Message')
        else:
            pass
        self.__save_resp_dict_as_pickle()

    def __search_pattern_add_to_status_dict(self, pattern, source, api_call_status_dict_param):
        temp = re.search(pattern, str(source), re.DOTALL)
        # re.DOTALL flags enables to match newlines too
        if temp:
            self.api_response_dict[api_call_status_dict_param] = temp.group(1)
        else:
            pass
            #self.api_response_dict[api_call_status_dict_param] = ''

    def __verify_response(self, resp, exp_str):
        if exp_str:
            tc_pass_bool = True if exp_str in resp else False
        else:
            tc_pass_bool = None
        return tc_pass_bool

    def __create_testcase_name(self, tc_name=None):
        tc_name = self.user_data.get('tc_name', '')
        validity = self.user_data.get('specificEndDate', '')

        if not validity:
            validity = self.user_data.get('validityPeriod', '')
        else:
            validity = validity.replace('/', '-')

        if not tc_name:

            commonname = self.csr_dict.get('cn', '') if hasattr(self, 'csr_dict') else ''
            tc_name = '{api}_{certProductType}_{validity}_{commonname}'.format(
                      api=self.api,
                      certProductType=self.user_data.get('certProductType', ''),
                      validity=validity,
                      commonname=commonname)
        self.user_data['tc_name'] = None
        return tc_name

    def __append_to_log(self, logfile, to_write):
        with codecs.open(logfile, 'a', 'utf-8') as w:
            w.write(to_write)

    def __create_api_call_result_dict(self):
        # move these result methods to another class and pass the self to the new class
        # using inheritance
        #: reset all result parameters to None for each call
        for attr in ('exp_str',
                     'pass_status_bool',
                     'pass_status_dict',
                     'tc_name',
                     'dict_tc_result_details'):
            setattr(self, attr, None)

        if not hasattr(self, 'outputfilePath'):
            self.outputfilePath = self.__set_log_file()

        self.exp_str = self.user_data.get('ExpectedResponse', '')
        self.pass_status_bool = self.__verify_response(resp=self.pretty_xml,
                                                       exp_str=self.exp_str)

        self.pass_status_dict = {True: 'PASS', False: 'FAIL', None: ''}
        self.tc_name = self.__create_testcase_name('tc_name')
        self.dict_tc_result_details = self.api_response_dict.copy()  # http://stackoverflow.com/questions/2465921/how-to-copy-a-dictionary-and-only-edit-the-copy
        self.dict_tc_result_details.update(
            {'tc_name': self.tc_name,
             'pass_status_bool': self.pass_status_bool,
             'api_name': self.api,
             'exp_str': self.exp_str,
             'post_data': self.post_data,
             'response': self.pretty_xml})

    def __cprint_api_call_result(self):
        self.api_call_result_str = None  # start from None for each call
        if self.debug:
            self.api_call_result_str = '{f}testcase name:{f}{tcname}{f}postdata:{f}{postdata}\
                    {f}response:{f}{response}{f}expected:{f}{expected}\
                    {f}testcase status:{f}{status}{f}'.format(
                        f=_FORMATTER,
                        tcname=self.tc_name,
                        postdata=pprint.pprint(self.post_data),
                        response=str(self.pretty_xml),
                        expected=self.exp_str,
                        status=self.pass_status_dict[self.pass_status_bool])
        else:
            self.api_call_result_str = ''

        self.cprint(self.api_call_result_str)

    def __append_api_call_result_to_log(self):
        ''' append api call result to log '''
        self.__append_to_log(logfile=self.outputfilePath, to_write=self.api_call_result_str)

    def __add_to_master_result(self):
        ''' add to master result '''
        if not hasattr(self, 'all_tc_result_details'):
            self.all_tc_result_details = ()
        #self.list_all_tc_result_details.append(self.dict_tc_result_details)
        self.all_tc_result_details += (self.dict_tc_result_details,)

    def cprint_summary_result(self):
        ''' cprint summary result '''
        f1 = '=' * 40
        self.cprint('cprinting Summary :\n{format1}'.format(format1=f1))
        if hasattr(self, 'all_tc_result_details'):
            for result in self.all_tc_result_details:
                result_string = '{f}\
                       \nTC::STATUS --> {tc_name}::{status}\
                       \n{f}\
                       \nEXPECTED:{expected}\
                       \n{f}\
                       \nRESPONSE:{response}---'.format(
                            tc_name=result['tc_name'],
                            status=self.pass_status_dict[result['pass_status_bool']],
                            expected=result['exp_str'],
                            response=result['response'][:200],
                            f=_FORMATTER)
                self.cprint(result_string)
            self.cprint('{format1}'.format(format1=_FORMATTER))
            self.cprint('response is stored in file {file}'.format(
                file=os.path.abspath(self.outputfilePath)))
        else:
            self.cprint('No results to cprint')

    def __verify_resp_prepare_report(self):
        self.__create_api_call_result_dict()
        self.__cprint_api_call_result()
        self.__append_api_call_result_to_log()
        self.__add_to_master_result()


    def __clean_pickle_files(self):
        #: clean all exising pickle files- when new lifecycle starts
        if self.is_new_enrollment:
            for f in os.listdir('.'):
                if '.pickle' in f:
                    os.remove(f)

    def __save_resp_dict_as_pickle(self):

        self._serialize_data(self.api_response_dict, self.pickle_file_name)
        # save all to temp.pickle
        self.temp_data[self.pickle_file_name] = self.api_response_dict
        # for vice2 approve operation we need latest tran id ( not of enroll)
        tran_id = self.api_response_dict.get('Transaction_ID', None)
        if tran_id:
            self.latest_tran_id = tran_id
            if self.api in ('enroll', 'Enrollment'):
                self.enrollment_tran_id = tran_id

        cert = self.api_response_dict.get('Certificate', None)
        if cert:
            self.latest_certificate = cert

        self._serialize_data(self.temp_data, 'temp.pickle')

    def _get_pickled_data(self, parameter, pickle_file=None):
        '''
        returns the desired parameter from the pickle Value
        else returns None if not found or file does not exist'''
        _status_dict_pickle = dict()

        if os.path.isfile(pickle_file):
            with open(pickle_file, 'rb') as f:
                _status_dict_pickle = pickle.load(f)
        else:
            return None

        return _status_dict_pickle.get(parameter, None)

    def __dump_cert_to_file(self, data=None, filename=None):
        if not data:
            if hasattr(self, 'api_response_dict'):
                data = self.api_response_dict.get('Certificate', '')
        if data:
            dirname = '{pickup_dir}'.format(pickup_dir='pickup_cert')
            if not os.path.exists(dirname):
                os.mkdir(dirname)

            temp = {'Microsoft': '.p7b'}
            ext = temp.get(self.user_data.get('serverType','dummy'), '.cer')

            filename = '{tc_name}{random}{extension}'.format(
                      tc_name=self.tc_name,
                      extension=ext,
                      random=str(time.time()).replace('.', '')
                      )
            filepath = os.path.join(dirname, filename).replace('*', 'wildcard')
            self.cprint('certificate is stored in file:{file}'.format(
                file=os.path.abspath(filepath)))
            with codecs.open(filepath, 'w', 'utf-8') as f:
                f.write(data)
            self.filepath_certificate_content = filepath
            return filepath

    def get_orignal_certificate(self):
        ''' for backward compatibility '''
        return self.get_cert_from_last_response()

    def get_enrollment_tran_id(self):
        ''' used to preserve tran id from enroll for get alternate operations '''
        if hasattr(self, 'enrollment_tran_id'):
            return self.enrollment_tran_id

        self._deserialize_pickle(self.temp_data, 'temp.pickle')
        tran_id = self.temp_data['enroll_status_dict.pickle'].get('Transaction_ID', None)
        return tran_id

    def get_latest_tran_id(self):
        if hasattr(self, 'latest_tran_id'): #: if the enroll failed
            return self.latest_tran_id
        else:
            return None

    def get_cert_from_last_response(self):
        return self.latest_certificate




    def test_viceAPI(self, api, using_alg=''):
        ''' This function takes the api name,
            posts the test date to the server(base url)
            does not return anything  '''
        self.cprint('{f}'.format(f=_FORMATTER))
        if True:
            self.api = api
            self.using_alg = using_alg  #: intermediate data for alternate cert
            self.__clean_pickle_files()

            self.initialize_required_data()
            if self.require_csr : self._gen_csr()  #: generate csr if required for the post
            if self.req_prep_post_data_from_input :self._prepare_post_data()   #: copy required user data to post data
            #if self.using_data : self.__append_intermediate_data()  #: appends transaction_id or original cert
            #self.__set_connection_params()
            self.__post_webservice_request()
            self.__dump_cert_to_file()  #: if certificate part of response -> dump



    @property
    def is_vice2(self):
        return self.api in _VICE2_API_SET_

    @property
    def is_vice1(self):
        return self.api in _VICE1_API_SET_


    @property
    def require_csr(self):
        return self.api in {'enroll',
                            'renew',
                            'replace',
                            'Enrollment',
                            'Renewal',
                            #'getAlternate' - feature removed
                            }

    @property
    def req_prep_post_data_from_input(self):
        ''' apis not mentioned does not require manual test data for post
            the required values provided in api call level
            exception: resetChallengePhrase is not included as the parameter is
            'challenge' and requires a new value

        '''
        return self.api in {'enroll',
                            'renew',
                            'replace',
                            'Enrollment',
                            'Renewal',
                            'getAlternate'}


    @property
    def is_new_enrollment(self):
        return self.api in {'enroll',
                            'Enrollment'}

    @property
    def post_url(self):
        ''' build the url to post '''
        if self.is_vice2:
            return 'https://{host}/vswebservices/rest/services/{api}'.format(
                            host=self.vice2BaseURL,
                            api=self.api)
        if self.is_vice1:
            return 'https://{host}/cgi-bin/vice.exe'.format(host='')

    def get_encryption_type(self, signatureAlgorithm):
        ''' guess encryption type from signature alg
        '''
        d_alg = {'sha256WithRSAEncryption': 'RSA',
                 'sha1WithRSAEncryption': 'RSA',
                 'sha256WithRSAEncryptionFull': 'RSA',
                 'DSAwithSHA256': 'DSA',
                 'ECDSAwithSHA256andRSAroot': 'ECC',
                 'ECDSAwithSHA256': 'ECC',
                 }
        return d_alg.get(signatureAlgorithm, 'dummy')


    @property
    def pickle_file_name(self):
        api = self.api
        if self.is_new_enrollment: # works for vice1 and vice2
            api = 'enroll'
        return '{api}{suffix}.pickle'.format(api=api,
                                             suffix='_status_dict')


    @property
    def org(self):
       
        if self.user_data.get('org', None):
            self._org = self.user_data['org']
        else:
            self._org = self.env['org']
        return self._org

    @property
    def user_data(self):
        '''this may be useless '''
        return self._user_data

    @user_data.setter
    def user_data(self, value):
        self._user_data = dict(value)


class API(doAPI):
    """docstring for API -> Interface to call  VICE2 APIs
       here inheritance is better than composition
       because setting the test data from outside is complex
       with composition

    """

    def __init__(self, env=None, user_data=None, EACJurhash=None, socks_proxy=False, debug=True):
        
        super().__init__(env, user_data, EACJurhash, socks_proxy, debug) # python 3
        self.cprint('Enviroment set to:', self.vice2BaseURL)


    def VICE2enroll(self):
        ''' enroll a cert '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()
        self.test_viceAPI(api='enroll')

    def VICE2renewByTranId(self, tran_id=None):
        ''' renew a cert using transaction_id '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()

        if tran_id is None:
            tran_id = self.get_latest_tran_id()

        self.initialize_postdata_dict['original_transaction_id'] = tran_id
        self.test_viceAPI(api='renew')


    def VICE2renewByOriginalCert(self):
        ''' renew a cert using original certificate '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()
        cert = self.get_cert_from_last_response()
        self.initialize_postdata_dict['original_certificate'] = cert
        self.test_viceAPI(api='renew')



    def VICE2replaceByTranId(self, tran_id=None):
        ''' replace a cert using transaction_id '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()

        if tran_id is None:
            tran_id = self.get_latest_tran_id()
        if tran_id:
            self.initialize_postdata_dict['original_transaction_id'] = tran_id
            self.test_viceAPI(api='replace')
        else:
            self.cprint('tran_id not found')

    def VICE2replaceByOriginalCert(self, using_data='original_certificate'):
        ''' replace using original_certificate '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()
        cert = self.get_cert_from_last_response()
        self.initialize_postdata_dict['original_certificate'] = cert
        self.test_viceAPI(api='replace')

    def VICE2getAlternate(self, using_alt_alg):
        ''' get alternate cert for the original_certificate'''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()

        tran_id = self.get_latest_tran_id()
        self.initialize_postdata_dict['original_transaction_id'] = tran_id

        #self.enrollment_alg = self.user_data['alg']
        # encryption alg is derived from signature alg
        enrollment_sigAlg = self.user_data['signatureAlgorithm']

        self.user_data['signatureAlgorithm'] = using_alt_alg
        #self.user_data['alg'] = self.get_encryption_type  ## handled in csr gen
        self.test_viceAPI(api='getAlternate', using_alg=using_alt_alg)
        #self.user_data['alg'] = self.enrollment_alg
        self.user_data['signatureAlgorithm'] = enrollment_sigAlg


    def VICE2getAlternateRSA(self):
        ''' get alternate RSA for the original_certificate'''
        self.VICE2getAlternate(using_data='original_transaction_id',
                          using_alt_alg='sha256WithRSAEncryption')

    def VICE2getAlternateDSA(self, api_data=None):
        ''' get alternate DSA for the original_certificate'''
        self.VICE2getAlternate(using_data='original_transaction_id',
                          using_alt_alg='DSAwithSHA256')

    def VICE2getAlternateECC(self):
        ''' get alternate ECC for the original_certificate'''
        self.VICE2getAlternate(using_data='original_transaction_id',
                          using_alt_alg='ECDSAwithSHA256')

    def VICE2getAlternateECCHybrid(self):
        ''' get alternate ECC hybrid rsa root '''
        self.VICE2getAlternate(using_data='original_transaction_id',
                          using_alt_alg='ECDSAwithSHA256andRSAroot')

    def VICE2gettokencounts(self):
        ''' get token counts '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()
        self.user_data['ExpectedResponse'] = '0x00'
        self.test_viceAPI(api='gettokencounts')

    def VICE2getVettedOrgsAndDomains(self):
        ''' get vetted orgs '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()
        self.user_data['ExpectedResponse'] = '0x00'
        self.test_viceAPI(api='getVettedOrgsAndDomains')

    def VICE2getEnrollmentFields(self):
        ''' get enrollment fields '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()
        self.user_data['ExpectedResponse'] = '0x00'
        self.test_viceAPI(api='getEnrollmentFields')

    def VICE2pickup(self, tran_id=None):
        ''' pick up certificate for approved cert '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()

        if tran_id is None:
            tran_id = self.get_latest_tran_id()

        self.initialize_postdata_dict['transaction_id'] = tran_id # set in post_data
        self.user_data['ExpectedResponse'] = '0x00'
        self.test_viceAPI(api='pickup')
        self.certSerial = Utils().get_serial_number_from_x509_pem(self.api_response_dict.get('Certificate'))
        #self.original_certificate = self.api_response_dict.get('Certificate', None)

    def VICE2approve(self,
                    tran_id=None, 
                    ctLogOption=None, 
                    validityPeriod=None,
                    specificEndDate=None):
        ''' approve a pending cert '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()

        if tran_id is None:
            tran_id = self.get_latest_tran_id()

        self.initialize_postdata_dict['transaction_id'] = tran_id
        self.initialize_postdata_dict['ctLogOption'] = ctLogOption
        self.initialize_postdata_dict['validityPeriod'] = validityPeriod
        self.initialize_postdata_dict['specificEndDate'] = specificEndDate

        self.user_data['ExpectedResponse'] = '0x00'

        self.test_viceAPI(api='approve')
        if self.user_data.get('serverType', None) == 'Microsoft' and tran_id:
            self.cprint('certificate is in p7b format, need pick up to get pem')
            self.VICE2pickup()
        #self.original_certificate = self.api_response_dict.get('Certificate', None)

    def VICE2reject(self, tran_id=None):
        ''' reject a pending cert '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()

        if tran_id is None:
            tran_id = self.get_latest_tran_id()

        self.initialize_postdata_dict['transaction_id'] = tran_id # set in post_data
        self.test_viceAPI(api='reject')

    def VICE2resetChallengePhrase(self, challenge=None, tran_id=None):
        ''' reset challenge phrase for a certificate
        this does not require user data so passed to post data'''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()
        if tran_id is None:
            tran_id = self.get_latest_tran_id()

        self.initialize_postdata_dict['transaction_id'] = tran_id # set in post_data

        if challenge is not None:
            self.initialize_postdata_dict['challenge'] = challenge
        else:
            self.initialize_postdata_dict['challenge'] = self.user_data['challenge']

        self.test_viceAPI(api='resetChallengePhrase')


    def VICE2getAccountSetup(self, designation=None):
        ''' gets account features using api '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()
        self.initialize_postdata_dict['designation'] = designation
        self.test_viceAPI(api='getAccountSetup')

    def VICE2getAutoApprovalFlag(self):
        ''' get auto approval flag '''
        # dont mess with dictionary references while copying data
        self.VICE2getAccountSetup('AutoApprovalFlag')

    def VICE2TechSupportEmail(self):
        ''' get Tech support email '''
        # dont mess with dictionary references while copying data
        self.VICE2getAccountSetup('TechSupportEmail')

    def VICE2ProductAvailability(self):
        ''' get ProductAvailability for account '''
        # dont mess with dictionary references while copying data
        self.VICE2getAccountSetup('ProductAvailability')

    def VICE2DefaultAlgorithms(self):
        ''' get Default Algorithms '''
        # dont mess with dictionary references while copying data
        self.VICE2getAccountSetup('DefaultAlgorithms')

    def VICE2revoke(self):
        ''' revoke a cert using original certificate '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()
        self.cert_to_revoke = self.get_orignal_certificate()

        if self.cert_to_revoke is not None:
            #self.certSerial = Utils().get_serial_number_from_x509_pem(self.cert_to_revoke)

            self.initialize_postdata_dict['certSerial'] = self.certSerial
            self.initialize_postdata_dict['reason'] = 'Key compromise'
            self.initialize_postdata_dict['challenge'] = self.user_data['challenge']

            self.test_viceAPI(api='revoke')
        else:
            self.cprint('original certifiate NOT found')

    def VICE2deactivate(self):
        ''' deactivate a cert using original certificate '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()
        self.cert_to_deactivate = self.get_orignal_certificate()

        if self.cert_to_deactivate:
            certSerial = Utils().get_serial_number_from_x509_pem(self.cert_to_deactivate)

            self.initialize_postdata_dict['certSerial'] = certSerial
            self.initialize_postdata_dict['reason'] = 'Forgotten or lost password'
            self.initialize_postdata_dict['challenge'] = self.user_data['challenge']

            self.test_viceAPI(api='deactivate')
        else:
            self.cprint('original certifiate NOT found')

    def VICE2updateSubscriberContact(self, firstName=None, lastName=None, emailAddr=None, tran_id=None):
        '''update subscriber contact'''

        if tran_id is None:
            tran_id = self.get_latest_tran_id()
        self.initialize_postdata_dict['transaction_id'] = tran_id

        if firstName is not None:
            self.initialize_postdata_dict['firstName'] = firstName
        if lastName is not None:
            self.initialize_postdata_dict['lastName'] = lastName
        if emailAddr is not None:
            self.initialize_postdata_dict['emailAddr'] = emailAddr

        self.test_viceAPI('updateSubscriberContact')

    ''' VICE1 API CALLS FOR TESTING'''

    def VICE1Enrollment(self):
        ''' enroll using vice1 '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()
        self.user_data['ExpectedResponse'] = '&status=pending'
        self.test_viceAPI(api='Enrollment')
        #self.enrollment_tran_id = self.api_response_dict.get('Transaction_ID', None)


    def VICE1Renewal(self, tran_id=None):
        ''' renew vice1 '''
        # dont mess with dictionary references while copying data
        self.initialize_postdata_dict = dict()
        if tran_id is None:
            tran_id = self._get_pickled_data('Transaction_ID', 'enroll_status_dict.pickle')

        self.initialize_postdata_dict['original_transaction_id'] = tran_id
        self.initialize_postdata_dict['transaction_id'] = tran_id # set in post_data

        self.user_data['ExpectedResponse'] = '&status=pending'
        self.test_viceAPI(api='Renewal')

if __name__ == '__main__':
    pass
    # please use mssl_api_testcases.py to call these APIs
