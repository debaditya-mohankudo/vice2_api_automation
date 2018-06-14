# -*- coding: utf-8 -*-
import os
import random
import string
#from OpenSSL import crypto as c
import base64

try:
    import arrow
except:
    print('arrow not installed')

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except:
    print('cryptography not installed')


class Utils(object):
    def custom_print(self, log_text, toPrint=False):
        if toPrint:
            print(log_text)


    def decode_cert_with_openssl(self, cert_cer):
        cmd_certx509_decode = 'openssl x509 -noout -text -in  %s' %(cert_cer)
        decoded_text =  os.popen(cmd_certx509_decode).readlines()
        out_file = '%s.decoded.txt' %cert_cer[:-3]
        with open(out_file,'wb') as w:
            w.writelines(decoded_text)

    def _pfx2pem(self,cert_pfx):
        ''' convert pfx to pem '''
        self._pem_file_name = '%s.pem' %(cert_pfx[:-4])
        if not os.path.exists(self._pem_file_name):
            command_to_convert = "openssl pkcs12 -in %s -out %s -passin pass:password -nodes" %(cert_pfx, self._pem_file_name)
            os.popen(command_to_convert)
        print('the pem file is : %s' %(self._pem_file_name))



    def get_future_sslx(self,no_of_days):
        ''' adds the no of days and outputs future date (yyyy,mm,dd) '''
        today = arrow.utcnow()
        sslx = today.replace(days=no_of_days)
        print(sslx)
        return sslx

    def convert_sslx_to_timestamp(self,no_of_days):
        ''' adds the no of days to today and outputs future timestamp in
        certificate end date format
            e.g. today is 1st jan 2014
            convert_sslx_to_timestamp(3)
            outputs timestamp for |3rd jan 2014 23:59:59|
            NOT 4th jan 2014 00 00 00 |
            ( as per certificate end date format) '''
        sslx = self.get_future_sslx(no_of_days)
        print(sslx)
        validity_end_date = arrow.Arrow(sslx.year, sslx.month, sslx.day,
                                           23, 59, 59).replace(days=-1)
        print(validity_end_date, '->', validity_end_date.timestamp)
        return validity_end_date.timestamp

    def get_billing_type(self,no_of_days):
        if no_of_days % 365 != 0 and no_of_days > 365:
            oneMoreYear = 1
            billing_years = no_of_days // 365 + oneMoreYear
            billing_type = str(billing_years) + 'Y'
        else:
            billing_type = ''
        return billing_type

    def get_future_date(self,noOfDaysToAdd, strict=True):
        '''Returns (Today + noOfDaysToAdd) as a string. Format : mm/dd/yyyy'''
        import datetime
        futDate = ''
        if not noOfDaysToAdd:noOfDaysToAdd=0
        futDate = datetime.date.today() + datetime.timedelta(days=int(noOfDaysToAdd))
        if futDate.month < 10 :
            month = str(futDate.month)
            if strict:
                month = '0' + str(futDate.month)

        else :
            month = str(futDate.month)
        if futDate.day < 10 :
            day =  str(futDate.day) #str(0) +
            if strict:
                day = '0' + str(futDate.day)
        else :
            day = str(futDate.day)
        dateStr =  month + '/' + day + '/' + str(futDate.year)
        return dateStr

    def sslx_vice2_get_date(self,daysORDate):
        ''' input may be no of days or a date in mm/dd/yyyy
            returns current date +_ no of days if integer else the input mm/dd/yyyy itself
        '''
        try:
            daysORDate = int(daysORDate)
        except:
            pass
        if isinstance(daysORDate, int):
            daysORDate = self.get_future_date(daysORDate)
        return daysORDate

    def gen_sans(self, howmany, domain, prefix=None):
      ''' returns a string of concatenated sans
      e.g. get_sans(2, 'bbtest.net') -->
      returns 'san1.bbtest.net,san2.bbtest.net'
      '''
      output = ''
      for i in xrange(howmany):
        if not prefix:
          output += Utils().random_word(8)+'.'+domain+','
        else:
          output += prefix + str(i) + '.'+domain+','
      return output[:-1]

    def set_subject_alt_namex(self, howmany, domain, dict_testdata, prefix):
      ''' sets the subject_alt_namex value in dict '''
      for i in xrange(howmany):
        key = 'subject_alt_name' +str(i+1)
        dict_testdata[key] = prefix + str(i) + '.'+ domain



    def get_uppercase(self,word):
        return str(word).upper()

    def random_word(self, length=5, population=''):
        '''Returns a random word for a given length
            Arguments = length (integer)
        '''
        import random,string
        if not population:
            population = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        #population = "1234567890"
        #chinese_population = "叫姐京九可老李零六吗妈么没美国过海好很会家见叫姐京九可老李零六吗妈么没美妹们明名".decode('utf-8')
        #mixed_population = "叫姐京aeiu".decode('utf-8')
        

        return ''.join(random.sample(population,int(length)))



    def yield_file_content(self,filename):
        """ returns a one line for each functiona call
        """
        with open(filename) as f:
            for line in f.readlines():
                yield line

    def generate_tc_dict_from_file(self, filename):
        """ returns an iterator object e.g. xrange()
        """
        tc_no = 0
        parameters_list = None
        for line in self.yield_file_content(filename):
            if not parameters_list and line.startswith('--'):
                parameters_list = line.replace('--', '').replace('\n', '').split(";")
                #print parameters_list
            elif parameters_list: # get values from tc if parameters found
                values_list = line.replace('\n', '').split(';')
                #print values_list
                if len(values_list) == len(parameters_list):
                    print(len(values_list), '--', len(parameters_list))
                    test_data_for_api_dict = dict(zip(parameters_list, values_list))
                    tc_no += 1
                    #print test_data_for_api_dict
                    yield test_data_for_api_dict ,tc_no
                #else:
                    #print 'no of values/parameters mismatch'
                    #print str(len(values_list))+' NOT equal'+ str(len(parameters_list))

    def get_extension_from_x509(self, cert_string, extn):
        cert = x509.load_pem_x509_certificate(cert_string.encode('utf-8'), default_backend())
        return cert.extensions.get_extension_for_oid(extn)


    def get_san_extension_from_x509(self, cert_string):
        return self.get_extension_from_x509(cert_string, x509.OID_SUBJECT_ALTERNATIVE_NAME)

    def dertopem_encoding(der_file, pem_file):
        ' convert der encoding to base64 encoding - no signature check - tbsCertificate'
        der_content = open(der_file, 'rb').read()
        open(pem_file, 'wb').write(base64.b64encode(der_content))

    def get_serial_number_from_x509_pem(self, pem_string):
        """
        gets serial_number from x509 cert, if it starts with 0 the parser returns 31 long only
        so added the required leading 0
        """
        if pem_string:
            pem_in_bytes = bytes(pem_string, 'utf-8')
            cert = x509.load_pem_x509_certificate(pem_in_bytes, default_backend())
            certSerial = hex(cert.serial_number)[2:]
            return (32 - len(certSerial)) * '0' + certSerial




if __name__ == '__main__':
    pass
    #print [('comment', 4), ('serverType', 1)] == Utils().map_mcelp_tdata_vice2({'additional_field9':1, 'additional_field3':4})
    #for i in Utils().yield_mcelp_to_vice_param(['additional_field3', 'additional_field9']):
    #    print i
    #print XLSUtils().get_tc_from_excel('test.xlsx')
    #print cryptoUtils().decode_cert_with_certUtil('pickup_cert/ServerSHA256withRSAEncryption1Y1393492883.cer')
    #print(Utils().get_future_sslx(370))