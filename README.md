# restest
  Makes HTTP request and does various assertions on the response Http Status Code, response text/json, elapsed time, files, response json schema validation,...

**Usage:**
  send(method, origin, path, params = None, data = None, json = None, headers = None, cookies = None, files = None, auth = None,
                timeout = None, allow_redirects = None, proxies = None, verify = True, stream = False, filename = None,
                cert = None, raiseForStatus = True, expectedOutput = None, setResponse = None, **kwargs)

  * method = GET/POST/PUT/DELETE
  * origin = Origin url. Ex: https://staging.qubewire.com
  * path = Path url. Ex: /api/v1/sign
  * data = data that goes inside requestBody
  * json = json data that goes inside requestBody. ex: {
          "applianceId": "775f5990-dccf-4a0d-93ec-42639a21d2ef",
          "name": "ping",
          "params": {"testKey": "testValue"}
        }
  * headers = headers dict. {"Content-Type": "image/gif", "Authorization":"token"}
  * cookies = cookies data
  * files = file path or list of file path. Ex: "/var/data/file.txt"
  * timeout = int timeout value
  * stream = default False. If set to True it will download the response into file.
  * filename = default None. Required if stream is True. Downloaded file will be saved in this filename.
  * raiseForStatus = default True. Raises as exception if http code if greater than 399.
  * expectedOutput = list. List of objects for response assertions.
  * setResponse = default None. If given the response object will be added to GLOBALS var with the given name as key.

__Comparators:__

    * length_eq or count_eq - Check length of body/str or count of elements equals value
    * equals or eq - Expected and actual are equals
    * str_eq - Values are Equal When Converted to String
    * not_equals - Expected and actual are not equals
    * less_than or lt - Actual is less than expected
    * greater_than or gt - Actual is greater than expected
    * less_than_or_equal or le - Actual is Lesser Than Or Equal to expected
    * greater_than_or_equal or ge - Actual is Greater Than or Equal to expected
    * contains - Actual contains expected
    * contained_by - Expected contains actual

__Status code:__ Following compartors are supported,

    Equals, Not Equals, Less than, Greater than, Less than or equals, Greater than or equals and contained by.

__JSON:__ Following compartors are supported,

    Equals and Contains.

__Text:__ Following compartors are supported,

    Equals, Not Equals, Contains, Contained by and Length Equals.

    Additionally, if ignore_case property set to True case sensitive is ignored.

__Elapsed time:__ Following compartors are supported,

    Equals, Less than, Less than or equals, Greater than and Greater than or equals

__File:__ File supports only equals comparator. File hashes will be compared.

__Example:__

POST_SUCCESS_SCHEMA = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "additionalProperties": False,
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z"
    }
  },
  "required": [
    "id"
  ]
}

task = {
          "applianceId": "appliance_id",
          "name": "ping",
          "params": {"testKey": "testValue"}
        }

expectedOutput = [{"comparator": "equals", "statusCode": 201},
        {"comparator": "lt", "elapsedTime": 0.5},
        {"validator": "schema", "json": "POST_SUCCESS_SCHEMA"}
      ]

```sendRequest(method = "POST", origin = "https://host:3000/", path = "/appliances/v1/task", json = task, setResponse =  "CREATE_TASK_RESPONSE", expectedOutput = expectedOutput)```

*expectedOutput = [{"comparator": "equals", "statusCode": 200},
        {"comparator": "lt", "elapsedTime": 0.5},
        {"comparator": "contains", "json": {"id": "GLOBALS['CREATE_TASK_RESPONSE'].json()['id']",
          "applianceId": "GLOBALS['GET_APPLIANCE_RESPONSE'].json()['id']", "name":"ping", "params": {"testKey":"testValue"},
          "status": "queued","statusDetails": {}}},
        {"validator": "schema", "json": "Schemas.Tasks.GET_SUCCESS_SCHEMA"}
        //Schemas.Tasks.GET_SUCCESS_SCHEMA = schema is be represented Tasks.py file with var name GET_SUCCESS_SCHEMA under Schemas folder and the same is imported in Main.py like import Schemas.Tasks

```sendRequest(method = "GET", origin = "https://host:3000/", path = "/appliances/v1/tasks/ + GLOBALS['CREATE_TASK_RESPONSE'].json()['id']", expectedOutput = expectedOutput)```
