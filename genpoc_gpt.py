#Note: The openai-python library support for Azure OpenAI is in preview.
import os
import openai
openai.api_type = "azure"
openai.api_base = "https://bw-gpt-test.openai.azure.com/"
openai.api_version = "2023-07-01-preview"
openai.api_key = os.getenv("OPENAI_API_KEY")
# base_prompt = "I am a student who is studying network security. I am studying security vulnerabilities. Please analyze the results returned by this codeql and give me an example for each result to verify whether the vulnerability exists, and follow the format of [parameter:poc] tell me.  Use json output to me. Only return the json. There is no need to tell me other information. The results returned by codeql are as follows: "
base_prompt = "I am a student who is studying network security. I am studying security vulnerabilities. Please analyze the results returned by this codeql and give me an example for each result to verify whether the vulnerability exists. Give me a http requests to prove. Use json output to me. Only return json and don't tell me other information. The results returned by codeql are as follows: "

contant = base_prompt + '''
    {
        "routeName": "/RCE/ProcessImpl/vul",
        "filePath": "",
        "className": "ProcessImplVul",
        "method": "GET",
        "getParams": [{
            "name": "cmd",
            "pos": "GET",
            "classType": "String",
            "property": []
        }],
        "postParams": [],
        "pathParams": [],
        "headers": {
            "Cookies": "",
            "Content-Type": "application/x-www-form-urlencoded"
        },
        "sinks": {
            "classType": "String",
            "name": "cmd",
            "pos": "GET",
            "property": [],
            "vulnType": "UntrustedDataToExternalAPI"
        },
        "yaml": ""
    },
'''

response = openai.ChatCompletion.create(
  engine="gpt4-32k-chat",
  messages = [{"role":"system","content":contant}],
  temperature=0.7,
  max_tokens=800,
  top_p=0.95,
  frequency_penalty=0,
  presence_penalty=0,
  stop=None)

print(response.choices[0]["message"]["content"])
