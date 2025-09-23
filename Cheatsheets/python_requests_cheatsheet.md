# Python Requests Cheat Sheet

A quick reference for using the Python `requests` library to interact with web APIs.
This library allows Python to send HTTP requests to websites or APIs and handle their responses easily. 
It can be used to fetch data from or send data to web APIS, download files without manually opening a browser. 

---

## 1. Install requests
```bash
pip install requests
```
## 2. Basic GET Request
```Python
import requests 
response = requests.get("https://api.example.com/data") #requests.get(...) sends a GET request to the URL provided
print(response.json()) #most APIs send data in JSON format, this line converts the JSON from the server into a Python dictionary or list
```
## 3. GET with parameters - fetchs data
```Python
params = {"key": "value"} #Params is a python dictionary holding data to send as query parameters to the server.
                            #Each key-value pair becomes key=valu
response = requests.get("https://api.example.com/data", params=params)
```

## 4. POST request - sends data to the server
```Python
data = {"username": "user", "Password": "pass"} #data is a dictionary holding login credential the user wants to login with 
response = requests.post("https://api.example.com/login", json=data) # request sends these credentials to the server. server checks if credentials are correct
```

## 5.Headers and authentication 
```Python
headers = {"Authorization": "Bearer YOUR_API_KEY"} #creates dictionairy called headers.
                                                   #Authorization is a key that tells the server who you are
                                                   #"Bearer YORU_API_KEY" is the token that proves you have permission to access the data
response = requests.get("https://api.example.com/data", headers=headers) #Requests.get() function that asks a website or API for some info
                                                                          #headers=headers - sends the authorization info created by the user so the server knows youre allowed to access the data
                                                                          #response = variable that stores the result
```

## 6. Download files
```Python
url = "https://example.com/file.zip" #stores url in variable called url
response = requests.get(url) #sends a request to that link to download the file. Sends result and stores it in response
with open("file.zip", "wb") as f: #opens a new file on the pc called file.zip in write-binary.
                                  #mode wb is needed for non-text files like zip files.
                                  #with makes sure the file is properly closed after writing 
    f.write(response.content)     # this writes the actual content of the file downloaded into "file.zip" on the pc 
```
## 7. Error handling 
```Python
try: #tries the code 
  response = requests.get("https://api.example.com/data") # tries to download data from URL, if no issues, python will just download the data
  response.raise_for_status() # checks the HTTP status code. if is isnt 200, this line raises an exception, which is then caught by the except block 
except requests.exceptions.RequestException as e: #catches any request-related errors (connection problems, timeout, bad status codes). Stores error into in variable e
  print("Error:", e) #prints the error
```
