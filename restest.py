import os
import logging
import time
import hashlib
import base64
import traceback

try:
    from urlparse import urljoin
except:
    from urllib.parse import urljoin

try:
    BaseString = basestring
except:
    BaseString = str

import requests
import json as jsonlib

csvLogger = logging.getLogger('csv')
csvLogger.addHandler(logging.NullHandler())

LENGTHEQUALS = ('length_eq', 'count_eq')
EQUALS = ('equals', 'eq')
STREQUALS = ('str_eq')
NOTEQUALS = ('not_equals')
LESSTHAN = ('less_than', 'lt')
GREATERTHAN = ('greater_than', 'gt')
LESSTHANOREQUALs = ('less_than_or_equal', 'le')
GREATERTHANOREQUALS = ('greater_than_or_equal', 'ge')
CONTAINS = ('contains')
CONTAINEDBY = ('contained_by')

COMPARATORS_DESCRIPTION = {

    LENGTHEQUALS: "Check length of body/str or count of elements equals value",
    EQUALS: "Equals",
    STREQUALS: "Values are Equal When Converted to String",
    NOTEQUALS: "Not Equals",
    LESSTHAN: "Less Than",
    GREATERTHAN: "Greater Than",
    LESSTHANOREQUALs: "Lesser Than Or Equal To",
    GREATERTHANOREQUALS: "Greater Than Or Equal To",
    CONTAINS: "Contains",
    CONTAINEDBY: "Contained By"
}

try:
    BaseString = basestring
except NameError:
    BaseString = str

class Restest():

    def __init__(self, serverUrl, method, endpointPath, auth = None, timeout = None, allowRedirects = None,
                 proxies = None, verify = True, params = None, data = None, json = None, headers = None,
                 cookies = None, files = None, filename = None, expectedOutput = None, stream = False,
                 cert = None, raiseForStatus = True, logRequest = True, logResponse = True):

        self.hasWarnings = False
        self.response = self.__send(method = method, serverUrl = serverUrl, endpointPath = endpointPath, params = params,
                                    data = data, json = json, headers = headers, cookies = cookies, files = files, auth = auth,
                                    timeout = timeout, allowRedirects = allowRedirects, proxies = proxies, verify = verify,
                                    stream = stream, cert = cert, raiseForStatus = raiseForStatus, logRequest = logRequest,
                                    logResponse = logResponse, expectedOutput = expectedOutput, filename = filename)

    def __send(self, serverUrl, method, endpointPath, params, data, json, headers, cookies, files, auth, timeout,
               allowRedirects, proxies, verify, stream, filename, cert, raiseForStatus, expectedOutput, logRequest,
               logResponse):

        """sends request to given endpoint and returns the response
        Parameters:
            serverUrl - Server url. Ex: https://api.server.example.com
            endpointPath - endpoint path. Ex: /v1/method
            method - Value should be any one of get, post, delete and put
            params - Dictionary or bytes to be sent in the query string
            data - Dictionary, bytes, or file-like object to send in the body
            json - json data to send in the body
            headers - Dictionary of Http Headers to send
            cookies - Dict or CookieJar object to send
            files - list of file path
            auth - Auth tuple to enable Basic/Digest/Custom Http Auth
            timeout(float or tuple) - How long to wait for the server to send data before giving up, as a float,
                                   or a (connect timeout, read timeout) tuple
            allowRedirects (bool) - Boolean. Set to True if POST/PUT/DELETE redirect following is allowed.
            proxies = Dictionary mapping protocol to the URL of the proxy.
            verify - Default : True. If True, the SSL cert will be verified. A CA_BUNDLE path can also be provided.
            stream - Default : False. If False, the response content will be immediately downloaded.
            filename - If Stream is set to True, the response is downloaded and written into to the given filename.
                        If filename not given then filename created with current timestamp value.
            cert - if String, path to ssl client cert file (.pem). If tuple, ('cert', 'key') pair
        Returns:
            Response object
        Return type:
            requests.Response
        """

        url = urljoin(base = serverUrl, url = endpointPath)


        if logRequest:
            logging.debug('method: {method}\nurl: {url}\nparams: {params}\njson: {json}\nheaders: {headers}\ndata: {data}\n'
                         'timeout: {timeout}\nfiles:{files}'.format(method = method, url = url, params = params,
                                                                    json = jsonlib.dumps(json), headers = headers,
                                                                    data = data,timeout = timeout, files = files))

        response = None
        try:
            filesObj = {}
            if files:
                if isinstance(files, list):
                    for fileName in files:
                        filesObj.update({os.path.basename(fileName): open(fileName, 'rb')})
                elif isinstance(files, BaseString):
                    filesObj = {os.path.basename(files): open(files, 'rb')}
                elif isinstance(files, dict):
                    filesObj = files
                else:
                    logging.error("Input files is not of type list or str")
                    raise Exception("Input files is not of type list or str")

            if method.lower() == 'get':
                response = requests.get(url, params = params, data = data, json = json, headers = headers, cookies = cookies,
                                        files = filesObj, auth = auth, timeout = timeout, allow_redirects = allowRedirects,
                                        proxies = proxies, verify = verify, stream = stream, cert = cert)

            elif method.lower() == 'post':
                response = requests.post(url, params = params, data = data, json = json, headers = headers, cookies = cookies,
                                         files = filesObj, auth = auth, timeout = timeout, allow_redirects = allowRedirects,
                                         proxies = proxies, verify = verify, stream = stream, cert = cert)

            elif method.lower() == 'delete':
                response = requests.delete(url, params = params, data = data, json = json, headers = headers, cookies = cookies,
                                           files = filesObj, auth = auth, timeout = timeout, allow_redirects = allowRedirects,
                                           proxies = proxies, verify = verify, stream = stream, cert = cert)

            elif method.lower() == 'put':
                response = requests.put(url, params = params, data = data, json = json, headers = headers, cookies = cookies,
                                        files = filesObj, auth = auth, timeout = timeout, allow_redirects = allowRedirects,
                                        proxies = proxies, verify = verify, stream = stream, cert = cert)

            else:
                logging.error("method should be one of the value in ['get','post','put','delete']")
                raise Exception("method should be one of the value in ['get','post','put','delete']")

            if raiseForStatus == True:
                response.raise_for_status()

            if method.lower() == 'get' and stream == True:
                if filename == None:
                    filename = "download_{0}".format(int(time.time()))
                self.__downloadFile(response, filename = filename)

        except Exception as e:
            #Check response is not None as just checking response will not get into if condition in case of any error
            if response is not None:
                try:
                    logging.error("Error from exception part Response: \"{0}\" Status Code: \"{1}\" Reason: \"{2}\" Elapsed time: \"{3}\"".
                                 format(response.text, response.status_code, response.reason, response.elapsed.total_seconds()))
                except:
                    logging.error("Error from exception part Response: \"{0}\" Status Code: \"{1}\" Reason: \"{2}\" Elapsed time: \"{3}\"".
                                 format(response.text.encode('utf-8'), response.status_code, response.reason, response.elapsed.total_seconds()))

                csvLogger.debug('"{method}","{url}","{code}","{elapsedTime}"'.format(method = method, url = url,
                                                                                     code = response.status_code,
                                                                                     elapsedTime = response.elapsed.total_seconds()))
                raise Exception(traceback.format_exc())

            logging.error(str(e))
            raise Exception(traceback.format_exc())

        if logResponse:
            try:
                logging.debug("Response: \"{0}\" Status Code: \"{1}\" Reason: \"{2}\" Elapsed time: \"{3}\"".
                             format(response.text, response.status_code, response.reason, response.elapsed.total_seconds()))
            except:
                logging.debug("Response: \"{0}\" Status Code: \"{1}\" Reason: \"{2}\" Elapsed time: \"{3}\"".
                             format(response.text.encode('utf-8'), response.status_code, response.reason, response.elapsed.total_seconds()))

        csvLogger.debug('"{method}","{url}","{code}","{elapsedTime}"'.format(method = method, url = url,
                                                                             code = response.status_code,
                                                                             elapsedTime = response.elapsed.total_seconds()))
        if expectedOutput:
            self.__assertResponse(response = response, expectedResponse = expectedOutput, filename = filename)

        return response

    def __assertJsonEqual(self, json1, json2):

        def ordered(obj):
            if isinstance(obj, dict):
                return dict((x, y) for x, y in sorted((k, ordered(v)) for k, v in obj.items()))
            if isinstance(obj, list):
                gen = [ordered(x) for x in obj]

                if len(gen) > 0 and isinstance(gen[0], dict):
                    return sorted(gen, key=lambda x: sorted(x.keys()))

                return sorted(gen)
            else:
                return obj

        json1 = ordered(json1)
        json2 = ordered(json2)
        if json1 != json2:
            raise Exception("AssertionError: expectedJson: {0} actualJson: {1}".format(jsonlib.dumps(json1),
                                                                                       jsonlib.dumps(json2)))

    def __validateJson(self, expectedJson, responseJson, logValidationErrors = True):

        try:
            if logValidationErrors and not isinstance(responseJson, type(expectedJson)):
                logging.error("Expected input: {0} type: {1} is not matching with actual input: {2} type: {3}"
                              .format(expectedJson, type(expectedJson), responseJson, type(responseJson)))
            assert isinstance(responseJson, type(expectedJson))
            if isinstance(expectedJson, list):
                for value in expectedJson:
                    if isinstance(value, dict):
                        responseDictList = filter(lambda item: isinstance(item, dict), responseJson)
                        dictFound = False
                        l = []
                        for responseDict in responseDictList:
                            try:
                                if self.__validateJson(value, responseDict, logValidationErrors = False):
                                    dictFound = True
                                    break
                            except Exception as e:
                                l.append(e)
                                pass
                        if logValidationErrors and not dictFound:
                            logging.error("Expected dict: {0} not in actual JSON: {1}".format(value, responseDictList))
                        assert dictFound
                    else:
                        if logValidationErrors and value not in responseJson:
                            logging.error("Expected value: {0} is not in actual JSON: {1}".format(value, responseJson))
                        assert value in responseJson
            elif isinstance(expectedJson, dict):
                for key, value in expectedJson.items():
                    if isinstance(value, (list, dict)):
                        self.__validateJson(value, responseJson[key])
                    else:
                        if logValidationErrors and responseJson[key] != value:
                            logging.error("Expected val: {0} and actual val: {1} for key: {2} not matching".format(value, responseJson[key], key))
                        assert responseJson[key] == value
        except (AssertionError, KeyError):
            raise Exception("Input expected json: {0} is not a subset of responseJson: {1}".format(expectedJson, responseJson))

        return True

    def __assertResponse(self, response, expectedResponse, filename = None):

        for itemDict in expectedResponse:
            if "comparator" in itemDict and "statusCode" in itemDict:
                actualStatusCode = itemDict.get('statusCode')
                expectedStatusCode = response.status_code
                if itemDict.get("comparator").lower() in EQUALS:
                    if actualStatusCode != expectedStatusCode:
                        raise Exception("Actual status code: \"{0}\" doesn't match with expected status code: \"{1}\"".format(expectedStatusCode, actualStatusCode))
                elif itemDict.get("comparator").lower() in NOTEQUALS:
                    if actualStatusCode == expectedStatusCode:
                        raise Exception("Actual status code: \"{0}\" and expected status code: \"{1}\" are equals which is not expected".format(expectedStatusCode, actualStatusCode))
                elif itemDict.get("comparator").lower() in LESSTHAN:
                    if expectedStatusCode >= actualStatusCode:
                        raise Exception("Actual status code: \"{0}\" is not less than the with expected status code: \"{1}\"".format(expectedStatusCode, actualStatusCode))
                elif itemDict.get("comparator").lower() in GREATERTHAN:
                    if expectedStatusCode <= actualStatusCode:
                        raise Exception("Actual status code: \"{0}\" is not greater than the with expected status code: \"{1}\"".format(expectedStatusCode, actualStatusCode))
                elif itemDict.get("comparator").lower() in LESSTHANOREQUALs:
                    if expectedStatusCode > actualStatusCode:
                        raise Exception("Actual status code: \"{0}\" is not lesser than or equals to the expected status code: \"{1}\"".format(expectedStatusCode, actualStatusCode))
                elif itemDict.get("comparator").lower() in GREATERTHANOREQUALS:
                    if expectedStatusCode < actualStatusCode:
                        raise Exception("Actual status code: \"{0}\" is not greater than or equals to the expected status code: \"{1}\"".format(expectedStatusCode, actualStatusCode))
                elif itemDict.get("comparator").lower() in CONTAINEDBY:
                    if expectedStatusCode not in actualStatusCode:
                        raise Exception("Actual status code: \"{0}\" is not matching with any of the expected status code: \"{1}\"".format(expectedStatusCode, actualStatusCode))
                else:
                    raise Exception("Comparator: \"{0}\" not supported for statusCode".format(itemDict.get("comparator")))
            if "comparator" in itemDict and 'json' in itemDict:
                expectedJson = itemDict.get('json')
                actualJson = response.json()
                if isinstance(expectedJson, BaseString) and os.path.isfile(expectedJson):
                    expectedJson = jsonlib.load(open(expectedJson))
                if itemDict.get("comparator").lower() in EQUALS:
                    self.__assertJsonEqual(json1 = expectedJson, json2 = actualJson)
                elif itemDict.get("comparator").lower() in CONTAINS:
                    self.__validateJson(expectedJson, actualJson)
                elif itemDict.get("comparator").lower() in LENGTHEQUALS:
                    if expectedJson.get('expectedLength') != len(actualJson):
                        raise Exception("Response json length: \"{0}\" is not equal to expected length: \"{1}\"".format(len(actualJson), expectedJson.get('expectedLength')))
                else:
                    raise Exception("Comparator: \"{0}\" not supported for json".format(itemDict.get("comparator")))
            if "comparator" in itemDict and "text" in itemDict:
                expectedText = itemDict.get('text')
                if os.path.isfile(expectedText):
                    expectedText = open(expectedText).read()
                if itemDict.get('ignoreCase'):
                    expectedText = expectedText.strip().lower()
                    actualText = response.text.strip().lower()
                else:
                    expectedText = expectedText.strip()
                    actualText = response.text.strip()
                if itemDict.get("comparator").lower() in EQUALS:
                    if expectedText != actualText:
                        raise Exception("Response text: \"{0}\" doesn't match with expected text: \"{1}\"".format(actualText, expectedText))
                elif itemDict.get("comparator").lower() in NOTEQUALS:
                    if expectedText == actualText:
                        raise Exception("Response text: \"{0}\" is same as expected text: \"{1}\" but expected to be different".format(actualText, expectedText))
                elif itemDict.get("comparator").lower() in CONTAINS:
                    if expectedText not in actualText:
                        raise Exception("Response text: \"{0}\" doesn't contains expected text: \"{1}\"".format(actualText, expectedText))
                elif itemDict.get("comparator").lower() in CONTAINEDBY:
                    if actualText not in expectedText:
                        raise Exception("Expected text: \"{0}\" doesn't contains response text: \"{1}\"".format(expectedText, actualText))
                elif itemDict.get("comparator").lower() in LENGTHEQUALS:
                    if len(expectedText) != len(actualText):
                        raise Exception("Response text length: \"{0}\" is not equal to expected text length: \"{1}\"".format(len(actualText), len(expectedText)))
                else:
                    raise Exception("Comparator: \"{0}\" not supported for text".format(itemDict.get("comparator")))
            if "comparator" in itemDict and "elapsedTime" in itemDict:
                elapsedTimeError = None
                if itemDict.get("comparator").lower() in LESSTHAN:
                    if not response.elapsed.total_seconds() < itemDict.get('elapsedTime'):
                        elapsedTimeError =  "Actual elapsed time: {0} is not lesser than expected elapsed time: {1}".format(response.elapsed.total_seconds(), itemDict.get('elapsedTime'))
                elif itemDict.get("comparator").lower() in LESSTHANOREQUALs:
                    if not response.elapsed.total_seconds() <= itemDict.get('elapsedTime'):
                        elapsedTimeError = "Actual elapsed time: {0} is not lesser than or equals expected elapsed time: {1}".format(response.elapsed.total_seconds(), itemDict.get('elapsedTime'))
                elif itemDict.get("comparator").lower() in GREATERTHAN:
                    if not response.elapsed.total_seconds() > itemDict.get('elapsedTime'):
                        elapsedTimeError = "Actual elapsed time: {0} is not greater than expected elapsed time: {1}".format(response.elapsed.total_seconds(), itemDict.get('elapsedTime'))
                elif itemDict.get("comparator").lower() in GREATERTHANOREQUALS:
                    if not response.elapsed.total_seconds() >= itemDict.get('elapsedTime'):
                        elapsedTimeError = "Actual elapsed time: {0} is not greater than or equals expected elapsed time: {1}".format(response.elapsed.total_seconds(), itemDict.get('elapsedTime'))
                elif itemDict.get("comparator").lower() in EQUALS:
                    if not itemDict.get('elapsedTime') == response.elapsed.total_seconds():
                        elapsedTimeError = "Actual elapsed time: {0} and expected elapsed time: {1} are not equals".format(response.elapsed.total_seconds(), itemDict.get('elapsedTime'))
                else:
                    raise Exception("Comparator: \"{0}\" not supported for elapsed time".format(itemDict.get("comparator")))

                errorLevel = itemDict.get('errorLevel', 'error')
                if elapsedTimeError and errorLevel.lower() == 'error':
                    raise AssertionError(elapsedTimeError)
                elif elapsedTimeError:
                    self.hasWarnings = True
                    logging.warning(elapsedTimeError)
            if "comparator" in itemDict and "file" in itemDict:
                if itemDict.get("comparator").lower() in EQUALS:
                    expectedFileHash = self.__computeSha1Hash(filename = itemDict.get('file'))
                    actualFileHash = self.__computeSha1Hash(filename = filename)
                    if expectedFileHash != actualFileHash:
                        raise Exception("Expected file hash: {0} and downloaded file hash: {1} are different".
                                        format(expectedFileHash, actualFileHash))
                else:
                    raise Exception("Comparator: \"{0}\" not supported for file".format(itemDict.get("comparator")))
            if itemDict.get("validator") == "schema":
                schema = itemDict.get("json")
                errorLevel = itemDict.get('errorLevel', 'error')
                if isinstance(schema, BaseString) and os.path.isfile(schema):
                    schema = open(schema).read()
                try:
                    self.__validateJsonSchema(schema = schema, jsonResponse = response.json())
                except Exception as e:
                    if errorLevel.lower() == 'error':
                        raise Exception("Schema is not matched. Reason: {0}".format(traceback.format_exc()))
                    else:
                        self.hasWarnings = True
                        logging.warning("Schema is not matched. Reason: {0}, for Schema: {1}".
                                        format(e.message, response.json()))

    def __validateJsonSchema(self, schema, jsonResponse):

        from jsonschema import Draft4Validator
        d4Validator = Draft4Validator(schema)
        errors = sorted(d4Validator.iter_errors(jsonResponse), key=lambda e: e.path)

        # Converted to list for python3 compatibility
        errors = list(map(lambda error: 'Message: "{}" for the Path: "{}"'.
                          format(error.message, '-'.join(map(lambda path: str(path),error.path))), errors))

        if errors:
            raise Exception('\n'.join(errors))

    def __computeSha1Hash(self, filename):

        hasher = hashlib.sha1()
        with open(filename, 'rb') as fileObj:
            while True:
                buf = fileObj.read(10 * 1000 * 1000)
                if not buf:
                    break
                hasher.update(buf)
        return base64.b64encode(hasher.digest())

    def __downloadFile(self, response, filename, chunkSize = 1024):
       """
        Downloads file
       """

       with open(filename, 'wb') as fd:
           for chunk in response.iter_content(chunk_size = chunkSize):
               fd.write(chunk)